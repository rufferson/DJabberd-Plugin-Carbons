package DJabberd::Plugin::Carbons;
# vim: sts=4 ai:
use warnings;
use strict;
use base 'DJabberd::Plugin';

use constant {
	CBNSv2 => "urn:xmpp:carbons:2",
	FWNSv0 => 'urn:xmpp:forward:0'
};

our $logger = DJabberd::Log->get_logger();

=head1 NAME

DJabberd::Plugin::Carbons - Implements XEP-0280 Message Carbons

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 SYNOPSIS

Implements XEP-0280 Message Carbons - a part of XMPP Advanced Server IM Compliance [2016].

    <VHost mydomain.com>
	<Plugin DJabberd::Plugin::Carbons />
    </VHost>

=head1 METHODS

=head2 register($self, $vhost)

Register the vhost with the module. Sets up hooks at chains c2s-iq, deliver and
ConnectionClosing. As well as adds server feature C<urn:xmpp:carbons:2>.
=cut

sub run_before {
    return qw(DJabberd::Delivery::Local);
}

my %callmap = (
    'set-{'.CBNSv2.'}enable' => \&manage,
    'set-{'.CBNSv2.'}disable' => \&manage,
);
my %wraps = (
    '{'.CBNSv2.'}sent' => 1,
    '{'.CBNSv2.'}received' => 1,
);
sub register {
    my ($self,$vhost) = @_;
    my $manage_cb = sub {
	my ($vh, $cb, $iq) = @_;
	if(exists $callmap{$iq->signature}) {
	    $callmap{$iq->signature}->($self,$iq);
	    return $cb->stop_chain;
	}
	$cb->decline;
    };
    my $recv_cb = sub {
	my ($vh,$cb,$sz) = @_;
	if($sz->isa('DJabberd::Message') && $sz->from && $sz->to) {
	    return $cb->decline unless(precheck($sz));
	    my $to = $sz->to_jid;
	    # Skip CCing `to` if it is dead, Delivery::Local will do the
	    # needfull. Also applies to bare jid (which never has connection).
	    my $c;
	    return $cb->decline
		unless(($c = $self->vh->find_jid($to)) && $c->is_available);
	    # Local is selfish and always stops delivery chain. To execute self
	    # AFTER local we need to cheat it. But this will depend on whether
	    # delivery succeeds. If it doesn't - there's nowhere to cc anyway.
	    my $delivered = $cb->{delivered};
	    $cb->{delivered} = sub {
		$self->handle($sz, $to, 'received');
		$delivered->($cb);
	    }
	}
	$cb->decline;
    };
    my $send_cb = sub {
	my ($vh,$cb,$sz) = @_;
	if($sz->isa('DJabberd::Message') && $sz->from && $sz->to) {
	    if(precheck($sz)) {
		$self->handle($sz, $sz->from_jid, 'sent');
	    }
	}
	# Don't prevent the ball rolling
	return $cb->decline;
    };
    my $cleanup_cb = sub {
	my ($vh,$cb,$c) = @_;
	$self->disable($c->bound_jid)
	    if($c->bound_jid && $self->is_enabled($c->bound_jid));
	$cb->decline;
    };
    $self->{vhost} = $vhost;
    Scalar::Util::weaken($self->{vhost});
    # Inject management IQ handler
    $vhost->register_hook("c2s-iq",$manage_cb);
    # Deliver hook will handle incoming messages.
    $vhost->register_hook("deliver",$recv_cb);
    # And this one is for outgoing
    $vhost->register_hook("switch_incoming_client",$send_cb);
    # Need to remove dead clients to avoid broadcasting carbons
    $vhost->register_hook("ConnectionClosing",$cleanup_cb);
    $vhost->caps->add(DJabberd::Caps::Feature->new(CBNSv2));
    $self->{reg} = {};
}

sub vh {
    return $_[0]->{vhost};
}

sub precheck {
    my ($sz) = @_;

    # Privacy rules - strip and skip
    if((my @priv = grep{$_->element eq '{'.CBNSv2.'}private'}$sz->children_elements)
	&& grep{$_->element eq '{urn:xmpp:hints}no-copy'}$sz->children_elements)
    {
	# Receiving server should strip private element regardless
	$sz->remove_child($priv[0])
	    if($sz->connection && $sz->conneciton->vhost->handles_jid($sz->to));
	return 0;
    }
    return 0 if(!eligible($sz));
    return 1;
}

# TODO: move it to DJabberd::Message perhaps
=head2 <Class>::eligible($msg[, 160|280|313])

Generalized call to verify eligibility for Carbons (0280) , MAM (0313) and
Offline Delivery (0160).

$msg is a target DJabberd::Message object which eligibility needs to be
verified.

Second optional argument is eligibility semantic which defaults to XEP-0280.
Currently supported semantics are 280 (default), 160 and 313.
=cut

sub eligible {
    my ($sz, $fv) = @_;
    $fv ||= 280;
    my $type = $sz->attr('{}type');
    # Carbon copy is never eligible for anything
    return 0 if(grep{exists $wraps{$_->element}}$sz->children_elements);
    # Chats are always eligible except for 160, errors sometimes but who cares
    if(!$type || $type eq 'normal') {
	# Normals are with caveats
	return 1 if($fv == 160);
	if(grep {
		($_->element_name eq 'body' && ($_->children || $_->{raw})) ||
		($_->namespace eq 'urn:xmpp:receipts') ||
		($_->namespace eq 'http://jabber.org/protocol/chatstates')
	   } $sz->children_elements) {
	    return 1;
	}
    } elsif ($type eq 'chat' || $type eq 'error') {
	# 160 does not like chat states
	return 1 if($fv != 160);
	# chat SHOULD be stored offline, with the exception of messages that
	# contain only Chat State Notifications (XEP-0085) [XEP-0160, 3]
	return 1 if(grep {$_->ns ne 'http://jabber.org/protocol/chatstates'}
		        $sz->children_elements);
    }
    return 0;
}

=head2 $self->manage($iq)

A method which handles carbons management driven by DJabberd::IQ stanzas of
C<urn:xmpp:carbons:2> namespace. Only <enable> and <disable> tags are
recognised, anything else will generate <bad-request> error.
=cut

sub manage {
    my $self = shift;
    my $iq = shift;
    my $jid = $iq->connection->bound_jid;
    unless($iq->connection->vhost->uses_jid($iq->to_jid) || !$iq->to || $jid->eq($iq->to_jid)) {
	$iq->send_error("<error type='cancel'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>");
	return;
    }
    delete $iq->attrs->{'{}to'}; # just to ensure
    if($iq->first_element->element_name eq 'disable') {
	$self->disable($jid);
    } elsif($iq->first_element->element_name eq 'enable') {
	$self->enable($jid);
    } else {
	$iq->send_error("<error type='cancel'><bad-request xmlns='urn:ietf:params:xml:ns:xmpp-stanzas'/></error>");
	return;
    }
    my $xml = "<iq type='result' id='".$iq->id."' to='".$jid->as_string."'/>";
    $iq->connection->log_outgoing_data($xml);
    $iq->connection->write(\$xml);
}

=head2 $self->enable($jid)

This method enables carbons for current session represented by full $jid.
=cut

sub enable {
    my ($self,$jid) = @_;
    $self->{reg}->{$jid->as_bare_string} = {} unless($self->{reg}->{$jid->as_bare_string});
    $self->{reg}->{$jid->as_bare_string}->{$jid->as_string} = 1;
    $logger->debug("Enabling Message Carbons for ".$jid->as_string);
}

=head2 $self->disable($jid)

The method to disable carbons on the session represented by full $jid.
If that was the last subscriber - it will entirely remove the user from
the list of interested jids.
=cut

sub disable {
    my ($self,$jid) = @_;
    if($self->{reg}->{$jid->as_bare_string}) {
	delete $self->{reg}->{$jid->as_bare_string}->{$jid->as_string};
	delete $self->{reg}->{$jid->as_bare_string} unless(keys(%{$self->{reg}->{$jid->as_bare_string}}));
	$logger->debug("Disabling Message Carbons for ".$jid->as_string);
    }
}

=head2 $self->is_disabled($jid)

The method returns true if given $jid has carbons enabled for the session.
=cut

sub is_enabled {
    my ($self,$jid) = @_;
    return (exists $self->{reg}->{$jid->as_bare_string} && $self->{reg}->{$jid->as_bare_string}->{$jid->as_string});
}

=head2 $self->enabled($jid)

This will return all users of the bare $jid which have their carbons sessions
enabled, excluding the one represented by the $jid itself.
=cut

sub enabled {
    my ($self,$jid) = @_;
    # Skip bare jids, cannot CC for them as it is handled by Delivery
    return () if($jid->is_bare);
    # Skip own jid as well, dups are not permitted even if the client can dedup
    my @ret = grep {$_ && $_ ne $jid->as_string} keys(%{$self->{reg}->{$jid->as_bare_string}})
	if(exists $self->{reg}->{$jid->as_bare_string} && ref($self->{reg}->{$jid->as_bare_string}));
    return @ret;
}
sub wrap_fwd {
    return DJabberd::XMLElement->new(FWNSv0,'forwarded',{xmlns=>FWNSv0},[@_]);
}

=head2 wrap($msg,$from,$to,$dir)

This static methods wraps message $msg into carbons <sent> or <received> tags
represented by $dir argument. $from and $to should represent corresponding
bare and full jid of the user which enabled carbons.
=cut

sub wrap {
    my ($msg,$from,$to,$dir) = @_;
    my $ret = DJabberd::Message->new('','message',
	{ '{}from' => $from, '{}to' => $to },
	[ DJabberd::XMLElement->new(CBNSv2,$dir,{xmlns=>CBNSv2},[ wrap_fwd($msg) ]) ]
    );
    $ret->set_attr('{}type',$msg->attr('{}type')) if($msg->attr('{}type'));
    return $ret;
}

=head2 $self->handle($msg)

The method handles message delivery to CC it to enabled resources.

The message is wrapped and delivered to all connected resources which enabled
the carbons. Message eligibility is checked at callback handler in the register
method. Delivery eligibility is reversed RFC6121 local delivery rule:
- if `to` is bare - skip as the message will be broadcasted anyway
- if `to` is full and there's active connection - deliver to all but matching
- if `to` is full and there's no active connection for it - this should unlock
conversation delivering it as to bare jid. The current implementation of the
DJabberd::Delivery::Local does the same as for bare here so skip as well.
- for `from` - just apply split horizon rule.
=cut

sub handle {
    my ($self,$msg,$for,$how) = @_;
    my @for = $self->enabled($for);
    $logger->debug("CCing to ".join(', ',(@for))) if(@for);
    foreach my$jid(@for) {
	my $conn = $self->vh->find_jid($jid);
	unless($conn) {
	    $self->disable(DJabberd::JID->new($jid));
	    next;
	}
	next unless($conn->is_available);
	my $cc = wrap($msg,$for->as_bare_string,$jid,$how);
	$cc->deliver($self->vh);
    }
}

=head1 AUTHOR

Ruslan N. Marchenko, C<< <me at ruff.mobi> >>

=head1 COPYRIGHT & LICENSE

Copyright 2016 Ruslan N. Marchenko, all rights reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.
=cut
1;
