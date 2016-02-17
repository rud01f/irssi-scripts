#
# whois (whois service query) irssi script
#
#  by rud0lf/IRCnet
#
# syntax:
#
#	/whois <nick/host/ip> [whois-server]
#	/whois -last
#
#

use strict;
use Socket;

use Irssi;

our $VERSION = "1.02";
our %IRSSI = (
	authors		=> 'rud0lf/IRCnet',
	contact		=> 'rud0lf -> IRCnet',
	name		=> 'IANA whois script',
	description	=> 'rud0lf`s testing script',
	license		=> 'GPL',
);

our $lastserver = "";
our $lastnick = "";
our $lasthost = "";

sub iana_whois {
	my ($data, $server, $witem) = @_;

	#use stored values
	if ($data eq "-last") {
		if ((!$lastserver) || (!$lasthost)) {
			printoutput("error -> no data from previous query");
			return;
		} 
	}
	else {
		my @args = split(" ", $data);
		#
		if (scalar @args > 2 || scalar @args == 0) {
			printoutput("error -> bad command syntax");
			return;
		} 
		my ($nickorhost, $wserver) = @args;
		if ($nickorhost =~ /[\w-]+\.[\w-]+/) {
			#hostname or ip given
			$lastnick = "";
			$lasthost = $nickorhost;
			$lastserver = $wserver;
		}	
		else {
			#nick given
			my @chans = $server->channels();
			my $foundnick;
			my $tmpn;
			foreach my $chan (@chans) {
				$tmpn = $chan->nick_find($nickorhost);
				if ($tmpn) {
					if ($tmpn->{host}) { 
						$foundnick = $tmpn; 
						last;
					} 
				}
			}
			if (!defined $foundnick) {
				printoutput("error -> nickname \"".$nickorhost."\" not found on any of synchronized channels!");
				return; 
			}
			$lastnick = $foundnick->{nick};
			my @zzz = split("@", $foundnick->{host});
			$lasthost = $zzz[1];
			$lastserver = $wserver;
		}		
	}	
	if (!$lastserver) { $lastserver = "whois.iana.org"; }
	printoutput('query for'.(!$lastnick?"":" (nick: $lastnick)").' host: '.$lasthost.' on '.$lastserver);
	
	my $nip = inet_aton($lastserver);
	if (!defined $nip) {
		printoutput("error -> can't solve server hostname");
		return; 
	}
	my $sock;
	if (!socket($sock, AF_INET, SOCK_STREAM, getprotobyname('tcp'))) {
		printoutput("error -> cannot open socket (".$!.")");
		return;
	}
	my $saddr = sockaddr_in(43, $nip);
	
	if (!connect($sock, $saddr)) {
		printoutput("error -> can't connect to server (".$!.")");
		return;
	}

	send($sock, $lasthost."\r\n", 0);
	my $redir = 0;
	while (my $line = <$sock>) {
		$line =~ s/\n//;
		print($line);
		if ($line =~ /whois:\s+(.+)/i) {
			$lastserver = $1;
			$redir = 1;
		}
	} 
	if ($redir) {
		printoutput("server seems to redirect you.. use \"/ianawhois -last\" to follow");
	}
	printoutput("end of iana-whois query");
}	

sub printoutput {
	my ($output) = @_;
	Irssi::print("%9IANA Whois:%9 ".$output, MSGLEVEL_CLIENTCRAP);
}

Irssi::command_bind('ianawhois', 'iana_whois');
