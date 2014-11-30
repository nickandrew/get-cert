#!/usr/bin/perl -w
#
#  Fetch a certificate from an SSL server, save it and show its md5 fingerprint
#  For use with fetchmail
#  (C) 2010, Nick Andrew <nick@nick-andrew.net>  Licensed under GPL v3+
#
#  Usage: get-cert.pl -d directory -h host [-p port]
#
#  Options:
#    -d directory     Save SSL certificate text to a file in this directory
#    -h hostname      Host to connect to (certificate saved as $hostname.pem))
#    -p port          Port to connect to on host
#
#  After getting the certificate, c_rehash is called to create correct symbolic
#  links in the certificate directory. The sslfingerprint line is printed and
#  needs to be put into the .fetchmailrc file.

use strict;

use Getopt::Std qw(getopts);

use vars qw($opt_d $opt_h $opt_p);

getopts('d:h:p:');

$opt_d || die "Need option -d directory";
$opt_h || die "Need option -h hostname";

my $connect = $opt_h . ($opt_p ? ":$opt_p" : '');
my $filename = "$opt_d/$opt_h.pem";

if (!-d $opt_d) {
	die "No such directory: $opt_d";
}

if (!-f $filename) {
	my $data = getCertificate($connect);
	saveCertificate($filename, $data);
	my $rc = system("c_rehash $opt_d");
	print "c_rehash $opt_d finished, code $rc\n";
} else {
	print "Certificate exists in $filename\n";
}

my $fingerprint = getFingerprint($filename);
if ($fingerprint) {
	printf("# for fetchmail\n");
	printf("sslfingerprint \"%s\"\n", $fingerprint);
}

print "Done\n";

exit(0);

# -------------------------------------------------------------------------
# Retrieve a certificate from a host using openssl.
# Return a string containing the ASCII certificate.
# -------------------------------------------------------------------------

sub getCertificate {
	my ($connect) = @_;

	if (!open(P, "openssl s_client -connect $connect </dev/null |")) {
		die "Unable to open pipe to openssl to connect to $connect\n";
	}

	my $in_cert = 0;
	my $cert    = '';

	while (<P>) {
		if (/^-----BEGIN CERTIFICATE-----/) {
			$cert .= $_;
			$in_cert = 1;
			next;
		}

		if (/^-----END CERTIFICATE-----/) {
			$cert .= $_;
			$in_cert = 0;
			next;
		}

		if ($in_cert) {
			$cert .= $_;
		}
	}

	close(P);

	return $cert;
}

# ---------------------------------------------------------------------------
# Save an ascii certificate to a file.
# ---------------------------------------------------------------------------

sub saveCertificate {
	my ($filename, $data) = @_;

	# Write cert to disk
	if (!open(OF, ">$filename")) {
		die "Unable to open $filename for write - $!";
	}

	print OF $data;

	close(OF);
}

# ---------------------------------------------------------------------------
# Get the md5 fingerprint of a certificate. Used by fetchmail.
# ---------------------------------------------------------------------------

sub getFingerprint {
	my ($filename) = @_;

	if (!open(P, "openssl x509 -in $filename -noout -md5 -fingerprint|")) {
		die "Unable to open pipe to openssl x509 on $filename - $!";
	}

	my $f;

	while (<P>) {
		if (/MD5 Fingerprint=(.+)/) {
			$f = $1;
		}
	}

	close(P);

	return $f;
}
