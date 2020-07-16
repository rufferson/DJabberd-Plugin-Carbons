#!/usr/bin/perl
use strict;
use Test::More tests => 4;

use DJabberd;
DJabberd::Log::set_logger("main");
use DJabberd::VHost;
use DJabberd::Authen::AllowedUsers;
use DJabberd::Authen::StaticPassword;
use DJabberd::RosterStorage::InMemoryOnly;

use DJabberd::Plugin::Carbons;

my $domain = "example.com";

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
my ($my, $her) = ('partya@'.$domain, 'partyb@'.$domain);

my $res_ok = sub { ok($_[0] =~ /^<iq[^>]+type=['"]result['"]/, $_[0]) };
my $err_ok = sub { ok($_[0] =~ /^<iq[^>]+type=['"]error['"]/, $_[0]) };
my $forbidden = sub { ok($_[0] =~ /<error[^<]+<forbidden/m, $_[0]) };
my $disco_ok = sub { ok($_[0] =~ /<feature[^>]+(var=['"]urn:xmpp:carbons:2['"])/m, 'Has feature: '.($1 || 'Not Found')) };


my $test;
my $disco = DJabberd::XMLElement->new('http://jabber.org/protocol/disco#info', 'query', {xmlns=>'http://jabber.org/protocol/disco#info'},[]);
my $cb_on  = DJabberd::XMLElement->new(DJabberd::Plugin::Carbons::CBNSv2, 'enable',  { xmlns => DJabberd::Plugin::Carbons::CBNSv2 });
my $cb_off = DJabberd::XMLElement->new(DJabberd::Plugin::Carbons::CBNSv2, 'disable', { xmlns => DJabberd::Plugin::Carbons::CBNSv2 });
my $iq = DJabberd::IQ->new('jabber:client', 'iq',
    {
	xmlns=> 'jabber:client',
	'{}type' => 'get',
	'{}from' => $my,
	'{}to' => $domain,
	'{}id' => 'iq1',
    }, []);
my $fc = FakeCon->new($vhost, DJabberd::JID->new($my), sub { $test->(${$_[1]}) });
$iq->set_connection($fc);

##
# Discover feature advertisement
$iq->push_child($disco);
$test = $disco_ok;
$iq->process($fc);
$iq->remove_child($disco);

##
# Enable carbons
$iq->set_attr('{}type','set');
$iq->push_child($cb_on);
$test = $res_ok;
$iq->process($fc);

##
# Enable someone else's carbons
$test = $err_ok;
$iq->set_to($her);
$iq->process($fc);
# reset back
$iq->remove_child($cb_on);
$iq->set_to($domain);

##
# Disable carbons
$iq->set_attr('{}type','set');
$iq->push_child($cb_off);
$test = $res_ok;
$iq->process($fc);


package FakeCon;

sub new {
    bless { vh=>$_[1], jid=>$_[2], wr=>$_[3], xl=>DJabberd::Log->get_logger('FakeCon::XML')}, $_[0];
}

sub is_server { 0 }
sub vhost { $_[0]->{vh} }
sub bound_jid { $_[0]->{jid} }
sub xmllog { $_[0]->{xl} }
sub write { $_[0]->{wr}->(@_) }

sub log_outgoing_data { $_[0]->{xl}->debug($_[1]) }
