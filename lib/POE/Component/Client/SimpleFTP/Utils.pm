package POE::Component::Client::SimpleFTP::Utils;

# ABSTRACT: Miscellaneous FTP utility functions

use parent 'Exporter';
our @EXPORT_OK = qw(
	code_preliminary code_success code_intermediate code_failure code_tls
	EOL mdtm_datetime
);
our %EXPORT_TAGS = (
	'code' => [
		qw( code_preliminary code_success code_intermediate code_failure code_tls ),
	],
);

=func code_preliminary

Tests whether the code is a 1yz code ( Positive Preliminary reply ) and returns a boolean value.

=cut

=func code_success

Tests whether the code is a 2yz code ( Positive Completion reply ) and returns a boolean value.

=cut

=func code_intermediate

Tests whether the code is a 3yz code ( Positive Intermediate reply ) and returns a boolean value.

=cut

=func code_failure

Tests whether the code is a 4yz or 5yz code ( Transient/Permanent Negative Completion reply ) and returns a boolean value.

=cut

=func code_tls

Tests whether the code is a 6yz code ( Protected reply ) and returns a boolean value.

=cut

# helper sub to validate a code before doing the actual comparison
sub _check_code {
	return if ! defined $_[0];
	return if length( $_[0] ) != 3;
	return if $_[0] !~ /^\d+$/;
	return 1;
}

# helper subs to figure out what a code is
sub code_preliminary { return if ! _check_code( $_[0] ); return substr( $_[0], 0, 1 ) == 1 }
sub code_success { return if ! _check_code( $_[0] ); return substr( $_[0], 0, 1 ) == 2 }
sub code_intermediate { return if ! _check_code( $_[0] ); return substr( $_[0], 0, 1 ) == 3 }
sub code_failure { return if ! _check_code( $_[0] ); return $_[0] =~ /^[45]/ }
sub code_tls { return if ! _check_code( $_[0] ); return substr( $_[0], 0, 1 ) == 6 }

=func EOL

Returns the end-of-line terminator as specified in RFC 959

=cut

sub EOL () { "\015\012" }

=func mdtm_datetime

Returns a L<DateTime> object representing the modification timestamp of a file. Useful for parsing L<POE::Component::Client::SimpleFTP/mdtm> replies!

NOTE: The MDTM format does not supply a timezone, you have to process that yourself!

On an error returns undef.

=cut

sub mdtm_datetime {
	my $mdtm = shift;

	# check to see if we received microseconds
	my $microseconds;
	if ( $mdtm =~ /^(\d+)\.(\d+)$/ ) {
		$mdtm = $1;
		$microseconds = $2;
	}

	require DateTime::Format::Strptime;
	my $strp = DateTime::Format::Strptime->new(
		# RFC 3659 pattern: YYYYMMDDHHMMSS.sss
		pattern => "%Y%m%d%H%M%S",
		on_error => 'undef',
	);
	my $dt = $strp->parse_datetime( $mdtm );
	if ( defined $dt ) {
		if ( defined $microseconds ) {
			# add it to the object!
			$dt->set_nanosecond( $microseconds * 1000 );
		}
		return $dt;
	} else {
		return undef;
	}
}

1;

=pod

=head1 SYNOPSIS

	use POE::Component::Client::SimpleFTP::Utils qw( :code );

	# in an event handler
	my $code = shift;
	if ( code_success( $code ) ) {
		print "FTP command OK\n";
	} else {
		warn "FTP command error!";
	}

=head1 DESCRIPTION

This module provides the various utility functions for use in your FTP application. You can import any sub listed in the POD or those tags:

=head2 code

Imports all of the code_* subs

=cut
