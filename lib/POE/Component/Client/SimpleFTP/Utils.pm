package POE::Component::Client::SimpleFTP::Utils;

# ABSTRACT: Miscellaneous FTP utility functions

use parent 'Exporter';
our @EXPORT_OK = qw(
	code_preliminary code_success code_intermediate code_failure code_tls
	EOL
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

# helper subs to figure out what a code is
sub code_preliminary { return substr( $_[0], 0, 1 ) == 1 }
sub code_success { return substr( $_[0], 0, 1 ) == 2 }
sub code_intermediate { return substr( $_[0], 0, 1 ) == 3 }
sub code_failure { return $_[0] =~ /^[45]/ }
sub code_tls { return substr( $_[0], 0, 1 ) == 6 }

=func EOL

Returns the end-of-line terminator as specified in RFC 959

=cut

sub EOL () { "\015\012" }

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
