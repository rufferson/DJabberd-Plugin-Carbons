#!/usr/bin/perl
use strict;
use Test::More tests => 8;

use DJabberd;
DJabberd::Log::set_logger("main");
use DJabberd::VHost;
use DJabberd::Authen::AllowedUsers;
use DJabberd::Authen::StaticPassword;
use DJabberd::RosterStorage::InMemoryOnly;

use DJabberd::Plugin::Carbons;
use DJabberd::Delivery::OfflineStorage;

my $domain = "example.com";
my $dother = "example.org";

my $cc = DJabberd::Plugin::Carbons->new();
$cc->finalize();

my $plugs = [
            DJabberd::Authen::AllowedUsers->new(policy => "deny",
                                                allowedusers => [qw(partya partyb)]),
            DJabberd::Authen::StaticPassword->new(password => "password"),
            DJabberd::RosterStorage::InMemoryOnly->new(),
	    $cc,
            DJabberd::Delivery::Local->new,
            DJabberd::Delivery::S2S->new
	];
my $vhost = DJabberd::VHost->new(
            server_name => $domain,
            s2s         => 1,
            plugins     => $plugs,
        );

my ($me, $she) = ('partya', 'partyb');
my ($my, $her) = ('partya@'.$domain, 'partyb@'.$dother);
my @ids=map{"ccoid$_"}(1..5);

my $mcheck = sub {
    my $x = shift;
    my $oid = $x->attr('{}id');
    my ($id) = grep{$_ eq $oid}@ids;
    return $id;
};
my $stest = sub { check_xml($_[0], 'S')};
my $rtest = sub { check_xml($_[0], 'R')};

my $no_cc = sub {
    my $m = shift;
    my $id = $mcheck->($m);
    if($id) {
	ok((grep{$_->element_name eq 'body'}$m->children_elements),$m->innards_as_xml);
	return 1;
    }
    return -1;
};
my $test = $no_cc;
##
# Setup the stage - two connections for the same user with different resources
my $err_ok = sub { ok($_[0] =~ /^<iq[^>]+type=['"]error['"]/, $_[0]) };
my $h1=DJabberd::SAXHandler->new;
my $h2=DJabberd::SAXHandler->new;
my $p1=DJabberd::XMLParser->new(Handler => $h1);
my $p2=DJabberd::XMLParser->new(Handler => $h2);
my $wtest = sub { my ($s,$x)=@_;eval{$p1->parse_chunk(ref($x)?${$x}:$x)} or fail($@.': '.$s) };
$p1->parse_chunk("<stream:stream xmlns:stream='jabber:client'>");
$p2->parse_chunk("<stream:stream xmlns:stream='jabber:client'>");
my $fc1 = FakeCon->new($vhost, DJabberd::JID->new("$my/test1"), sub {$wtest->(@_)}, sub{$rtest->(@_)}, sub{$stest->(@_)});
my $fc2 = FakeCon->new($vhost, DJabberd::JID->new("$my/test2"), sub {$wtest->(@_)}, sub{$rtest->(@_)}, sub{$stest->(@_)});
my $cb = DJabberd::Callback->new({registered=>sub{}});
$vhost->register_jid(DJabberd::JID->new($my), 'test1', $fc1, $cb);
$cb->reset;
$vhost->register_jid(DJabberd::JID->new($my), 'test2', $fc2, $cb);
$h1->set_connection($fc1);
$h2->set_connection($fc2);
# Staging complete
##

##
# First enable carbons for fc2
my $cb_on = DJabberd::XMLElement->new(DJabberd::Plugin::Carbons::CBNSv2, 'enable', { xmlns => DJabberd::Plugin::Carbons::CBNSv2 });
my $iq = DJabberd::IQ->new('jabber:client', 'iq', {
	xmlns=> 'jabber:client',
	'{}type' => 'set',
	'{}from' => $my,
	'{}to' => $domain,
	'{}id' => 'iq1',
    }, []);
$iq->push_child($cb_on);
$iq->set_connection($fc2);
$iq->process($fc2);

##
# Now send some message to the non-existing resource - should be broadcasted by Delivery::Local but not cc'd
# +2 ok
my $msg = DJabberd::Message->new('jabber:client', 'message', {
	xmlns=>'jabber:client',
	'{}from' => $her,
	'{}to' => "$my/test3",
	'{}id' => 'ccoid1',
    },
    [
	DJabberd::XMLElement->new('jabber:client','body',{xmlns=>'jabber:client'},[],'Hola!'),
    ]);
# no_cc test is pre-set
$msg->deliver($vhost);

##
# Send a message to the bare - should be identical to the above
$msg = DJabberd::Message->new('jabber:client', 'message', {
	xmlns=>'jabber:client',
	'{}from' => $her,
	'{}to' => $my,
	'{}id' => 'ccoid2',
    },
    [
	DJabberd::XMLElement->new('jabber:client','body',{xmlns=>'jabber:client'},[], "¿Cómo está?"),
    ]);
$msg->deliver($vhost);

##
# Now reply from non-cc-enabled full (fc1) - should cc on fc2
$msg = DJabberd::Message->new('jabber:client', 'message', {
	xmlns=>'jabber:client',
	'{}to' => $her,
	'{}id' => 'ccoid3',
    },
    [
	DJabberd::XMLElement->new('jabber:client','body',{xmlns=>'jabber:client'},[], "Hola! Bien! фыčí"),
    ]);
$msg->set_connection($fc1);
$test = \&check_cc;
DJabberd::Connection::ClientIn::filter_incoming_client_builtin($vhost, 0, $msg, $fc1);

##
# And now reply from cc-enabled - should not be cc'd to fc1 - we cannot
# positively test it without s2s, just don't increase test count
$msg = DJabberd::Message->new('jabber:client', 'message', {
	xmlns=>'jabber:client',
	'{}to' => $her,
	'{}id' => 'ccid4',
    },
    [
	DJabberd::XMLElement->new('jabber:client','body',{xmlns=>'jabber:client'},[], "¿y tú?"),
    ]);
$msg->set_connection($fc2);
DJabberd::Connection::ClientIn::filter_incoming_client_builtin($vhost, 0, $msg, $fc2);

##
# And final one - send message to non-cc jid, should be copied to fc2
$msg = DJabberd::Message->new('jabber:client', 'message', {
	xmlns=>'jabber:client',
	'{}from' => 't800@sky.net',
	'{}to' => $fc1->bound_jid->as_string,
	'{}id' => 'ccoid5',
    },
    [
	DJabberd::XMLElement->new('jabber:client','body',{xmlns=>'jabber:client'},[], "I need a vacation."),
    ]);
$test = sub {
    my $x = shift;
    if($x->to eq $fc1->bound_jid->as_string) {
	return $no_cc->($x);
    } else {
	return check_cc($x);
    }
};
$msg->deliver($vhost);

##########################################################################
# Test processing machinery
##########################################################################
sub check_xml {
    $DJabberd::VHost::logger->debug($_[1].': '.$_[0]->as_xml);
    if(my$ret = check_msg(@_)) {
	return fail($_[0]->innards_as_xml) if($ret<0);
	return;
    }
    if(my$ret = check_iq(@_)) {
	return fail($_[0]->innards_as_xml) if($ret<0);
	return;
    }
    fail("XML: ".$_[0]->as_xml);
}

sub check_msg {
    my $x = shift;
    if($x->element_name eq 'message') {
	return $test->($x);
    }
    return 0;
}
sub check_cc {
    my $x = shift;
    if($x->element_name eq 'message') {
	my $r = $x->first_element;
	if($r->element =~ /\{urn:xmpp:carbons:2\}(received|sent)/) {
	    my $f = $r->first_element;
	    if($f->element eq '{urn:xmpp:forward:0}forwarded') {
		my ($m) = grep{$_->element eq '{jabber:client}message'}$f->children_elements;
		if($m && DJabberd::Plugin::Carbons::eligible($m, 280)) {
		    ok($mcheck->($m), $m->innards_as_xml);
		    return 1;
		}
	    }
	}
	return -1;
    }
    return 0;
}

sub check_iq {
    my $x = shift;
    if($x->element_name eq 'iq') {
	my $f = $x->first_element;
	if($x->attr('{}id') eq 'iq1') {
	    ok($x->attr('{}type') eq 'result', $x->as_xml);
	    return 1;
	}
	fail($x->as_xml);
	return -1;
    }
    return 0;
}

package FakeCon;

sub new {
    bless { vh=>$_[1], jid=>$_[2], wr=>$_[3], sr=>$_[4], ss=>$_[5],
	xl=>DJabberd::Log->get_logger('FakeCon::XML'), in_stream => 1}, $_[0];
}

sub is_server { 0 }
sub is_available { 1 }
sub vhost { $_[0]->{vh} }
sub bound_jid { $_[0]->{jid} }
sub xmllog { $_[0]->{xl} }
sub write { $_[0]->{wr}->(@_) }
sub log_outgoing_data { $_[0]->{xl}->debug($_[1]) }
sub on_stanza_received { $_[0]->{sr}->($_[1]) }
sub send_stanza { $_[0]->{ss}->($_[1]) }
sub is_authenticated_jid { DJabberd::Connection::ClientIn::is_authenticated_jid(@_) }
