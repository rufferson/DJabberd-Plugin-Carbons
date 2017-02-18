package DJabberd::Plugin::Carbons;
# vim: sts=4 ai:
use warnings;
use strict;
use base 'DJabberd::Plugin';

use constant {
	CBNSv2 => "urn:xmpp:carbons:2",
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

sub register {
    my ($self,$vhost) = @_;
    my $manage_cb = sub {
	my ($vh, $cb, $iq) = @_;
	if($iq->first_element->namespace eq CBNSv2) {
	    $self->manage($iq);
	    $cb->stop_chain;
	}
	$cb->decline;
    };
    my $handle_cb = sub {
	my ($vh,$cb,$sz) = @_;
	$self->handle($sz) if($sz->isa('DJabberd::Message') && $sz->from && $sz->to);
	$cb->decline;
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
    # Deliver hook will handle outgoing and incoming messages.
    $vhost->register_hook("deliver",$handle_cb);
    # Need to remove dead clients to avoid broadcasting carbons
    $vhost->register_hook("ConnectionClosing",$cleanup_cb);
    $vhost->caps->add(DJabberd::Caps::Feature->new(CBNSv2));
    $self->{reg} = {};
}

sub vh {
    return $_[0]->{vhost};
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
    my @ret = grep {$_ && $_ ne $jid->as_string} keys(%{$self->{reg}->{$jid->as_bare_string}})
	if(exists $self->{reg}->{$jid->as_bare_string} && ref($self->{reg}->{$jid->as_bare_string}));
    return @ret;
}
sub wrap_fwd {
    return DJabberd::XMLElement->new('urn:xmpp:forward:0','forwarded',{},[@_]);
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
	[ DJabberd::XMLElement->new(CBNSv2,$dir,{},[ wrap_fwd($msg) ]) ]
    );
    $ret->set_attr('{}type',$msg->attr('{}type')) if($msg->attr('{}type'));
    return $ret;
}

=head2 $self->handle($msg)

The method handles message delivery to CC it to enabled resources.

If message is eligible and not private - it is wrapped and delivered to all
matching C<from> and C<to> local users which enabled the carbons.
=cut

sub handle {
    my ($self,$msg) = @_;
    my $type = $msg->attr('{}type');
    # Check eligibility
    return unless((!$type or $type eq 'chat' or $type eq 'normal' or $type eq 'error')
	and grep {$_->element_name eq 'body' && $_->children} $msg->children_elements);
    # Honour message hints
    return if(grep{$_->element eq '{urn:xmpp:hints}no-copy'} $msg->children_elements);
    # Honour private exclusions and remove it
    if(my @priv=grep {$_->element eq '{'.CBNSv2.'}private'} $msg->children_elements) {
	$msg->remove_child($priv[0]);
	return;
    }
    my $from = $msg->from_jid;
    my $to = $msg->to_jid;
    my @from = $self->enabled($from);
    my @to = $self->enabled($to);
    $logger->debug("CCing to ".join(', ',(@from,@to))) if(@from or @to);
    foreach my$jid(@from) {
	my $cc = wrap($msg,$from->as_bare_string,$jid,'sent');
	$cc->deliver($self->vh);
    }
    foreach my$jid(@to) {
	my $cc = wrap($msg,$to->as_bare_string,$jid,'received');
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
