#!/usr/bin/env perl

# Memcache audit tool
# Copyright 2012, Rémi Paulmier (BSD)
#

use FileHandle;
use strict;
use warnings;

use Getopt::Long qw(:config gnu_getopt);
use Net::Pcap;

sub help()
{
	die("
$0 [--help|-h] [--iface|-i dev] [--filter|-f expr] [-p]

    -h, --help         print this help
    -i, --iface        interface you wanna sniff (default is: lo)
    -f, --filter       pcap filter (default is: tcp dst port 11211)
    -p, --promisc      set promiscuous mode (default is: off)
    -s, --snaplen      set snap length (default is: 128)

");
}

# autoflush stdout
$|++;

# getopts
my ($opt_help, $opt_iface, $opt_filter, $opt_promisc, $opt_snaplen) = (undef, "lo", "tcp dst port 11211", undef, 128);

GetOptions('iface=s' => \$opt_iface, 'i=s' => \$opt_iface,
           'filter=s' => \$opt_filter, 'f=s' => \$opt_filter,
           'promisc' => \$opt_promisc, 'p' => \$opt_promisc,
           'snaplen=i' => \$opt_snaplen, 's=i' => \$opt_snaplen,
           'help' => \$opt_help, 'h' => \$opt_help) or &help;

&help if (defined($opt_help));

$opt_promisc = defined($opt_promisc) ? 1 : 0;

my($err, $net, $mask, $filter, $pcap);

# look at the interface
Net::Pcap::lookupnet($opt_iface, \$net, \$mask, \$err) == 0 ||
die "Net::Pcap::lookupnet failed.  Error was $err";

# open the pcap fd
$pcap = Net::Pcap::open_live($opt_iface, $opt_snaplen, $opt_promisc, 0, \$err) or die "Can't create packet descriptor.  Error was $err";

# compile a filter
Net::Pcap::compile($pcap, \$filter, $opt_filter, 1, $mask) == 0  or die "Unable to compile filter string '$opt_filter'\n";

# apply it to our pcap device
Net::Pcap::setfilter($pcap, $filter);

# main loop
my $count=0;
Net::Pcap::loop($pcap, -1, \&process_pkt, \$count);

# close
Net::Pcap::close($pcap);
exit 0;

# process the packet
sub process_pkt {
	my($user, $hdr, $pkt) = @_;

	my($mac_src) = 6;
	my($source_mac) = sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
	                          ord( substr($pkt, $mac_src, 1) ),
	                          ord( substr($pkt, $mac_src+1, 1) ),
	                          ord( substr($pkt, $mac_src+2, 1) ),
	                          ord( substr($pkt, $mac_src+3, 1) ),
	                          ord( substr($pkt, $mac_src+4, 1) ),
	                          ord( substr($pkt, $mac_src+5, 1) ));
	my($mac_dst) = 0;

	my($destination_mac) = sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
	                          ord( substr($pkt, $mac_dst, 1) ),
	                          ord( substr($pkt, $mac_dst+1, 1) ),
	                          ord( substr($pkt, $mac_dst+2, 1) ),
	                          ord( substr($pkt, $mac_dst+3, 1) ),
	                          ord( substr($pkt, $mac_dst+4, 1) ),
	                          ord( substr($pkt, $mac_dst+5, 1) ));

	my($ip_src) = 26; #+4
	my($ip_dst) = 30; #+4
	my($ip_opt) = 34; #+4

	my($tcp_src) = 38; #+2
	my($tcp_dst) = 40; #+2
	# seq +4
	# ack +4
	# hdr ... +4
	# chksum +2 urg+2
	# options +3 padding +1

	my($data_start) = 66;

	my($source) = sprintf("%d.%d.%d.%d",
	                      ord( substr($pkt, $ip_src, 1) ),
	                      ord( substr($pkt, $ip_src+1, 1) ),
	                      ord( substr($pkt, $ip_src+2, 1) ),
	                      ord( substr($pkt, $ip_src+3, 1) ));

	my($destination) = sprintf("%d.%d.%d.%d",
	                           ord( substr($pkt, $ip_dst, 1) ),
	                           ord( substr($pkt, $ip_dst+1, 1) ),
	                           ord( substr($pkt, $ip_dst+2, 1) ),
	                           ord( substr($pkt, $ip_dst+3, 1) ));
	$$user++;
	return if ($data_start > length($pkt));
	
	my $data = substr($pkt, $data_start);
	my @lines = split '\r\n', $data;

	if ($#lines >= 0) {
		print "$source > $destination: ";
		map {
			print "[$_] ";
		} @lines;
		print "\n";
	}
}
