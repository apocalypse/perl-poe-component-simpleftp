#!/usr/bin/perl
package LsClient;
use strict;
use warnings;

# a simple client to list a directory

#sub POE::Component::Client::SimpleFTP::DEBUG () { 1 };

use MooseX::POE::SweetArgs;
use POE::Component::Client::SimpleFTP;

with qw(
	MooseX::Getopt
);

has hostname => (
	isa => 'Str',
	is => 'ro',
	required => 1,
);

has port => (
	isa => 'Int',
	is => 'ro',
	default => 21,
);

has usetls => (
	isa => 'Bool',
	is => 'ro',
	default => 0,
);

has username => (
	isa => 'Str',
	is => 'ro',
	required => 1,
);

has password => (
	isa => 'Str',
	is => 'ro',
	required => 1,
);

has path => (
	isa => 'Str',
	is => 'ro',
	default => '/',
);

# our ftp object
has ftp => (
	traits => ['NoGetopt'],
	isa => 'POE::Component::Client::SimpleFTP',
	is => 'rw',
	weak_ref => 1,
	init_arg => undef,
);

sub START {
	my $self = shift;

	$self->ftp( POE::Component::Client::SimpleFTP->new(
		remote_addr => $self->hostname,
		remote_port => $self->port,
		username => $self->username,
		password => $self->password,
		( $self->usetls ? ( tls_cmd => 1, tls_data => 1 ) : () ),
	) );

	# now we just wait for the connection to succeed/fail
	return;
}

event _child => sub { return };

event connected => sub {
	my $self = shift;

	# do nothing hah

	return;
};

event connect_error => sub {
	my( $self, $code, $string ) = @_;

	die "CONNECT error: $code $string";

	return;
};

event login_error => sub {
	my( $self, $code, $string ) = @_;

	die "LOGIN error: $code $string";

	return;
};

event authenticated => sub {
	my $self = shift;

	# Okay, get the list!
	$self->ftp->yield( 'ls', $self->path );

	return;
};

event ls_error => sub {
	my( $self, $code, $string, $path ) = @_;

	die "ls error: $code $string";

	return;
};

event ls_connected => sub {
	my( $self, $path ) = @_;

	# do nothing hah

	return;
};

event ls_data => sub {
	my( $self, $input ) = @_;

	print "$input\n";

	return;
};

event ls => sub {
	my( $self, $path ) = @_;

	# done with the listing, we disconnect
	$self->ftp->yield( 'quit' );

	return;
};

# run the client!
my $ftp = LsClient->new_with_options;
POE::Kernel->run;
