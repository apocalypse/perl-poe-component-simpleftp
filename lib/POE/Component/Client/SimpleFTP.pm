package POE::Component::Client::SimpleFTP;

# ABSTRACT: A simple FTP client library for POE

use POE::Component::Client::SimpleFTP::Utils qw( :code EOL );
use MooseX::POE::SweetArgs;
use POE;
use POE::Wheel::SocketFactory;
use POE::Wheel::ReadWrite;
use POE::Filter::Stream;
use POE::Filter::Line;
use POE::Driver::SysRW;

use Socket qw( INADDR_ANY AF_INET SOCK_STREAM sockaddr_in inet_ntoa );

# list of things that is unimplemented
# full TLS support - check the RFCs
# FXP ( server<->server ) transfers
# 4.1.2.  TRANSFER PARAMETER COMMANDS ( RFC 959 )
#  This implies that the server must "remember" the applicable default values.
#  ( no need to send TYPE over and over! )
# intelligent NAT detection
# full ipv6 testing/support
# RFC 959 commands:
# * ACCT
# * SMNT
# * REIN
# * STRU
# * MODE
# * STOU
# * APPE
# * ALLO
# * REST
# * ABOR
# RFC 2228 commands:
# * ADAT
# * CCC
# * MIC
# * CONF
# * ENC
# RFC 2389 commands:
# * FEAT
# RFC 2640 commands:
# * the entire thing :)
# RFC 2773 commands:
# * the entire thing :)
# RFC 3659 commands:
# * REST
# * MLST
# * MLSD
# RFC 5795 commands:
# * the entire thing :)

BEGIN {

=func DEBUG

Enable this if you want to get debugging output. Do it like this:

	sub POE::Component::Client::SimpleFTP::DEBUG () { 1 }
	use POE::Component::Client::SimpleFTP;

The default is: false

=cut

	if ( ! defined &DEBUG ) { *DEBUG = sub () { 0 } }
}

=attr alias

The alias this component will use. You can send commands to the ftpd in 2 ways:

	my $ftp = POE::Component::Client::SimpleFTP->new( ... );
	$poe_kernel->post( 'ftp', 'cd', 'foobar' );

	# Or, you can use the yield sub:
	$ftp->yield( 'cd', 'foobar' );

The default is: ftp

=cut

has alias => (
	isa => 'Str',
	is => 'ro',
	default => 'ftp',
);

=attr username

The FTP username you will be sending to the server.

required.

=cut

has username => (
	isa => 'Str',
	is => 'ro',
	required => 1,
);

=attr password

The FTP password you will be sending to the server.

required.

=cut

has password => (
	isa => 'Str',
	is => 'ro',
	required => 1,
);

=attr remote_addr

The IP address of the FTP server to connect to. Can be a DNS hostname or IPv4/6 string.

required.

=cut

has remote_addr => (
	isa => 'Str',
	is => 'ro',
	required => 1,
);

=attr remote_port

The port of the FTP server to connect to.

The default is: 21

=cut

has remote_port => (
	isa => 'Int',
	is => 'ro',
	default => 21,
);

=attr local_addr

The local IP address to bind to for all connections to the server.

The default is: INADDR_ANY ( let the OS decide )

=cut

has local_addr => (
	isa => 'Str',
	is => 'ro',
	default => INADDR_ANY,
);

=attr local_port

The local port to bind to for the control connection to the server. If you need to change the data connection's port, please
change the L</local_data_port> attribute.

The default is: 0 ( let the OS decide )

=cut

has local_port => (
	isa => 'Int',
	is => 'ro',
	default => 0,
);

=attr local_data_port

The local port to bind to for the data connection to the server. Must be a different port than the L</local_port> attribute!

The default is: 0 ( let the OS decide )

=cut

has local_data_port => (
	isa => 'Int',
	is => 'ro',
	default => 0,
);

=attr tls_cmd

A boolean value to enable/disable TLS encryption of the command connection. If you want to use this,
you must have L<POE::Component::SSLify> installed!

The default is: false

=cut

has tls_cmd => (
	isa => 'Bool',
	is => 'ro',
	writer => '_set_tls_cmd',
	default => 0,
);

=attr tls_data

A boolean value to enable/disable TLS encryption of the data connection. If you want to use this,
you must have L<POE::Component::SSLify> installed!

The default is: false

=cut

has tls_data => (
	isa => 'Bool',
	is => 'ro',
	writer => '_set_tls_data',
	default => 0,
);

=attr timeout

A value specifying the timeout in seconds for the initial connection to the FTP server.

The default is: 120

=cut

has timeout => (
	isa => 'Int',
	is => 'ro',
	default => 120,
);

=attr connection_mode

Determine what connection mode we will be using when opening the data connection to the server. In "active" mode,
the server will be connecting to us. In "passive" mode we will be connecting to the server. You usually need "passive" mode
if you are behind a firewall.

The default is: passive

=cut

{
	use Moose::Util::TypeConstraints;

	has connection_mode => (
		isa => enum( [ qw( active passive ) ] ),
		is => 'ro',
		default => 'passive',
	);
}

### internal attributes

# the socketfactory/readwrite wheels for the command connection
has cmd_sf => (
	isa => 'Maybe[POE::Wheel::SocketFactory]',
	is => 'rw',
	init_arg => undef,
);

has cmd_rw => (
	isa => 'Maybe[POE::Wheel::ReadWrite]',
	is => 'rw',
	init_arg => undef,
);

# the socketfactory/readwrite wheels for the data connection
has data_sf => (
	isa => 'Maybe[POE::Wheel::SocketFactory]',
	is => 'rw',
	init_arg => undef,
);

has data_rw => (
	isa => 'Maybe[POE::Wheel::ReadWrite]',
	is => 'rw',
	init_arg => undef,
);

has input_buffer => (
	isa => 'Str',
	is => 'rw',
	init_arg => undef,
	default => '',
);

has input_buffer_code => (
	isa => 'Int',
	is => 'rw',
	init_arg => undef,
);

# the session that spawned us and receives events from us
has _master => (
	isa => 'Int',
	is => 'rw',
	init_arg => undef,
);

# helper sub to simplify sending events to the master
sub tell_master {
	my( $self, $event, @args ) = @_;

	$poe_kernel->post( $self->_master, $event, @args );
}

# the internal state of the connection
has state => (
	isa => 'Str',
	is => 'rw',
	default => 'connect',
	init_arg => undef,
);

# holds what "simple" command we are processing when state is 'simple_command'
has simple_command => (
	isa => 'Str',
	is => 'rw',
	init_arg => undef,
);

# holds whatever data the "complex" command needs
has complex_command => (
	isa => 'Maybe[HashRef[Str]]',
	is => 'rw',
	default => sub { {} },
	init_arg => undef,
);

# translation from posted events to ftp commands
my %command_map = (
	'cd'		=> "CWD",
	'mkdir'		=> "MKD",
	'rmdir'		=> "RMD",
	'ls'		=> "LIST",
	'dir'		=> "NLST",
	'get'		=> "RETR",
	'put'		=> "STOR",
	'delete'	=> "DELE",
	'quote'		=> "QUOT",
);

my %summary_map;
$summary_map{ lc( $command_map{ $_ } ) } = $_ for keys %command_map;

# build our "simple" command handlers
foreach my $cmd ( qw( cd cdup delete mdtm mkdir noop pwd rmdir site size stat syst type help quit quote ), keys %summary_map ) {
	event $cmd => sub {
		my( $self, @args ) = @_;
		my $command = $cmd;

		# are we already sending a command?
		if ( $self->state ne 'idle' ) {
			die "Unable to send '$cmd' because we are processing " . $self->state;
		}

		# do we need to translate the command?
		if ( exists $command_map{ $cmd } ) {
			$command = $command_map{ $cmd };
		} else {
			if ( exists $summary_map{ $cmd } ) {
				$cmd = $summary_map{ $cmd };
			}
		}

		# store the command we are processing then send it
		$self->simple_command( $cmd );
		$self->command( 'simple_command', $command, @args );
		return;
	};
}

event _child => sub {
	return;
};

sub BUILD {
	my $self = shift;

	# Did we enable TLS mode?
	if ( $self->tls_cmd or $self->tls_data ) {
		eval 'require POE::Component::SSLify';
		if ( $@ ) {
			warn "Unable to use SSLify: $@";
			$self->_set_tls_cmd( 0 );
			$self->_set_tls_data( 0 );
		}
	}

	# Make sure that the local_port and local_data_port is different!
	if ( $self->local_port == $self->local_data_port and $self->local_port != 0 ) {
		die "Please specify different local_port and local_data_port settings!";
	}

	# Figure out who called us so we store it for events
	$self->_master( $poe_kernel->get_active_session->ID );
}

# Okay, go connect to the host!
sub START {
	my $self = shift;

	warn "starting" if DEBUG;

	$poe_kernel->alias_set( $self->alias );

	# set a timeout before trying to connect
	$poe_kernel->delay( 'timeout_event' => $self->timeout );
	$self->cmd_sf( POE::Wheel::SocketFactory->new(
		SocketDomain	=> AF_INET,
		SocketType	=> SOCK_STREAM,
		SocketProtocol	=> 'tcp',
		RemoteAddress	=> $self->remote_addr,
		RemotePort	=> $self->remote_port,
		BindAddr	=> $self->local_addr,
		BindPort	=> $self->local_port,
		SuccessEvent	=> 'cmd_sf_connected',
		FailureEvent	=> 'cmd_sf_error'
	) );

	return;
}

event timeout_event => sub {
	my $self = shift;

	# Okay, we timed out doing something
	if ( $self->state eq 'connect' ) {
		# failed to connect to the server
		$self->tell_master( 'connect_error', 'timedout' );

		# nothing else to do...
		$self->_shutdown;
	} elsif ( $self->state eq 'complex_sf' ) {
		# timed out waiting for the data connection

		# TODO what goes here?
	} else {
		die "unknown state in timeout_event: " . $self->state;
	}

	return;
};

# shutdown the connection
sub _shutdown {
	my $self = shift;

	warn "shutdown" if DEBUG;

	# destroy our wheels
	$self->cmd_sf( undef );
	$self->cmd_rw( undef );

	# TODO destroy the data connection wheel

	# remove the timeout if it exists
	$poe_kernel->delay( 'timeout_event' );

	$poe_kernel->alias_remove( $self->alias );
}

=func yield

This method provides an alternative object based means of posting events to the component.
First argument is the event to post, following arguments are sent as arguments to the resultant post.

	my $ftp = POE::Component::Client::SimpleFTP->new( ... );
	$ftp->yield( 'cd', 'foobar' );

	# equivalent to:
	$poe_kernel->post( $ftp->alias, 'cd', 'foobar' );

=cut

sub yield {
	my( $self, @args ) = @_;
	$poe_kernel->post( $self->get_session_id, @args );
}

event cmd_sf_connected => sub {
	my( $self, $fh, $host, $port, $id ) = @_;

	warn "cmd_sf_connected" if DEBUG;

	# remove the timeout
	$poe_kernel->delay( 'timeout_event' );

	# convert it into a readwrite wheel
	$self->cmd_rw( POE::Wheel::ReadWrite->new(
		Handle	=> $fh,
		Filter	=> POE::Filter::Line->new( Literal => EOL ),
		Driver	=> POE::Driver::SysRW->new,
		InputEvent	=> 'cmd_rw_input',
		ErrorEvent	=> 'cmd_rw_error',
	) );

	return;
};

event cmd_sf_error => sub {
	my( $self, $operation, $errnum, $errstr, $id ) = @_;

	warn "cmd_sf_error $operation $errnum $errstr" if DEBUG;

	$self->tell_master( 'connect_error', "$operation error $errnum: $errstr" );

	# nothing else to do...
	$self->_shutdown;

	return;
};

event cmd_rw_input => sub {
	my( $self, $input, $id ) = @_;

	warn "cmd_rw_input(" . $self->state . "): '$input'" if DEBUG;

	# parse the input according to RFC 959
	# TODO put this code in POE::Filter::FTP or something?
	my( $code, $line );
	if ( $input =~ /^(\d\d\d)(\-?)(.+)$/ ) {
		$code = $1;
		my( $minus, $string ) = ( $2, $3 );
		$string =~ s/^\s+//;
		$string =~ s/\s+$//;

		if ( length $minus ) {
			# begin of multi-line reply
			warn "begin of multi-line($code): $string" if DEBUG;
			$self->input_buffer( $string );
			$self->input_buffer_code( $code );
			return;
		} else {
			# end of multi-line reply?
			if ( length( $self->input_buffer ) ) {
				# Make sure the code matches!
				if ( $self->input_buffer_code != $code ) {
					die "ftpd sent invalid reply: $input";
				} else {
					warn "end of multi-line: $string" if DEBUG;
					$line = $self->input_buffer . "\n" . $string;
					$self->input_buffer( '' );
				}
			} else {
				warn "got entire line($code): $string" if DEBUG;
				$line = $string;
			}
		}
	} else {
		# If we are in a multi-line reply, just collect the input
		if ( length( $self->input_buffer ) ) {
			# per the RFC, the first character should be padded by a space if needed
			$input =~ s/^\s//;
			warn "got multi-line input: $input" if DEBUG;
			$self->input_buffer( $self->input_buffer . $input );
		} else {
			die "ftpd sent invalid reply: $input";
		}
	}

	# process the input, depending on our state
	my $subref = "_ftpd_" . $self->state;
	$self->$subref( $code, $line );

	return;
};

event cmd_rw_error => sub {
	my( $self, $operation, $errnum, $errstr, $id) = @_;

	warn "cmd_rw_error $operation $errnum $errstr" if DEBUG;

	# TODO blah

	return;
};

event put => sub {
	my( $self, $file ) = @_;

	# are we already sending a command?
	if ( $self->state ne 'idle' ) {
		die "Unable to send 'put' because we are processing " . $self->state;
	}

	# start the put!
	warn "starting PUT for '$file'" if DEBUG;
	$self->complex_command( { 'cmd' => 'put', 'data' => $file } );

	# we start off by setting the TYPE
	$self->command( 'put_type', 'TYPE', 'I' );

	return;
};

# sets the state for a command and sends it over the control connection
sub command {
	my( $self, $state, $cmd, @args ) = @_;

	# If we don't have a readwrite wheel, then we can't send anything!
	if ( ! defined $self->cmd_rw ) {
		die "Unable to send '$cmd' as we aren't connected!";
	}

	# change to the specified state, then send the args!
	$self->state( $state );
	$cmd = uc $cmd; # to make sure
	if ( $cmd eq 'QUOT' ) {
		# user-defined string, send it as-is!
		$cmd = shift @args;
	}

	my $cmdstr = join( ' ', $cmd, @args );
	warn "sending command '$cmdstr'" if DEBUG;
	$self->cmd_rw->put( $cmdstr );
}

sub _ftpd_idle {
	my( $self, $code, $input ) = @_;

	die "unexpected text while we are idle: $code $input";
}

# should be the first line of text we received from the ftpd
sub _ftpd_connect {
	my( $self, $code, $input ) = @_;

	# TODO should we parse the code for failure replies?

	$self->tell_master( 'connected', $code, $input );

	# set our state to idle so we can start sending commands
	$self->state( 'idle' );

	# do we want TLS?
	if ( $self->tls_cmd ) {
		# begin TLS authentication procedure, as per RFC 2228 / 4217
		$self->command( 'tls_cmd', 'AUTH', 'TLS' );
	} else {
		# send the username!
		$self->command( 'user', 'USER', $self->username );
	}
}

sub _ftpd_tls_cmd {
	my( $self, $code, $input ) = @_;

	if ( code_success( $code ) ) {
		# Okay, time to SSLify the connection!
		my $socket = $self->cmd_rw->get_input_handle();
		$self->cmd_rw( undef );

		eval { $socket = POE::Component::SSLify::Client_SSLify( $socket, 'tlsv1' ) };
		if ( $@ ) {
			die "Unable to SSLify control connection: $@";
		}

		# set up the rw wheel again
		$self->cmd_rw( POE::Wheel::ReadWrite->new(
			Handle	=> $socket,
			Filter	=> POE::Filter::Line->new( Literal => EOL ),
			Driver	=> POE::Driver::SysRW->new,
			InputEvent	=> 'rw_input',
			ErrorEvent	=> 'rw_error',
		) );

		# Now, send the username!
		$self->command( 'user', 'USER', $self->username );
	} else {
		# server probably doesn't support AUTH TLS
		$self->tell_master( 'login_error', $code, $input );
		$self->state( 'idle' );
	}
}

sub _ftpd_pbsz {
	my( $self, $code, $input ) = @_;

	if ( code_success( $code ) ) {
		$self->command( 'prot', 'PROT', 'P' );
	} else {
		$self->tell_master( 'login_error', $code, $input );
		$self->state( 'idle' );
	}
}

sub _ftpd_prot {
	my( $self, $code, $input ) = @_;

	if ( code_success( $code ) ) {
		$self->tell_master( 'authenticated' );
	} else {
		$self->tell_master( 'login_error', $code, $input );
	}

	$self->state( 'idle' );
}

sub _ftpd_user {
	my( $self, $code, $input ) = @_;

	if ( code_success( $code ) ) {
		# no need for password ( probably anonymous account )

		# do we need to setup the data channel TLS stuff?
		if ( $self->tls_data ) {
			$self->command( 'pbsz', 'PBSZ', 0 );
		} else {
			$self->tell_master( 'authenticated' );
			$self->state( 'idle' );
		}
	} elsif ( code_intermediate( $code ) ) {
		# send the password!
		$self->command( 'password', 'PASS', $self->password );
	} else {
		$self->tell_master( 'login_error', $code, $input );
		$self->state( 'idle' );
	}
}

sub _ftpd_password {
	my( $self, $code, $input ) = @_;

	if ( code_success( $code ) ) {
		# do we need to setup the data channel TLS stuff?
		if ( $self->tls_data ) {
			$self->command( 'pbsz', 'PBSZ', 0 );
		} else {
			$self->tell_master( 'authenticated' );
			$self->state( 'idle' );
		}
	} else {
		$self->tell_master( 'login_error', $code, $input );
		$self->state( 'idle' );
	}
}

sub _ftpd_simple_command {
	my( $self, $code, $input ) = @_;

	if ( code_success( $code ) ) {
		$self->tell_master( $self->simple_command, $code, $input );
	} else {
		$self->tell_master( $self->simple_command . '_error', $code, $input );
	}

	$self->state( 'idle' );
}

sub _ftpd_put_type {
	my( $self, $code, $input ) = @_;

	if ( code_success( $code ) ) {
		# okay, we go ahead with the PASV/PORT command
		if ( $self->connection_mode eq 'passive' ) {
			$self->command( 'put_pasv', 'PASV' );
		} else {
			# Okay, create our listening socket
			$self->create_data_connection;
		}
	} else {
		$self->complex_command( undef );
		$self->tell_master( 'put_error', $code, $input );
		$self->state( 'idle' );
	}
}

sub _ftpd_put_pasv {
	my( $self, $code, $input ) = @_;

	if ( code_success( $code ) ) {
		# Got the server's data!
		my @data = $input =~ /(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)/;
		$self->complex_command->{'ip'} = join '.', @data[0 .. 3];
		$self->complex_command->{'port'} = $data[4]*256 + $data[5];

		# Okay, create our listening socket
		$self->create_data_connection;
	} else {
		$self->complex_command( undef );
		$self->tell_master( 'put_error', $code, $input );
		$self->state( 'idle' );
	}
}

sub create_data_connection {
	my $self = shift;

	# we now transition to the "complex" state
	# the "real" state is kept in $self->complex_command->{cmd}
	$self->state( 'complex_sf' );

	# the arguments to socketfactory depend on whether we are in active or passive mode
	my %sf_args = (
		SocketDomain	=> AF_INET,
		SocketType	=> SOCK_STREAM,
		SocketProtocol	=> 'tcp',
		SuccessEvent	=> 'data_sf_connected',
		FailureEvent	=> 'data_sf_error',

		BindAddr	=> $self->local_addr,
		BindPort	=> $self->local_data_port,
	);

	if ( $self->connection_mode eq 'passive' ) {
		# use the ip/port we already received
		$sf_args{ RemoteAddress } = $self->complex_command->{'ip'};
		$sf_args{ RemotePort } = $self->complex_command->{'port'};
	} else {
		# enable the Reuse param so we can sanely use the same local port
		$sf_args{ Reuse } = 1;
	}

	# create the socketfactory!
	$poe_kernel->delay( 'timeout_event' => $self->timeout );
	$self->data_sf( POE::Wheel::SocketFactory->new( %sf_args ) );

	# Now that we've created the SF, do we need to send the PORT data?
	if ( $self->connection_mode eq 'active' ) {
		my $socket = $self->data_sf->getsockname;
		my( $port, $addr ) = sockaddr_in( $socket );
		$addr = inet_ntoa( $addr );
		$addr = "127.0.0.1" if $addr eq "0.0.0.0";
		my @addr = split( /\./, $addr );
		my @port = ( int( $port / 256 ), $port % 256 );
		$self->command( 'complex_sf', 'PORT', join( ',', @addr, @port ) );
	}
}

event data_sf_connected => sub {
	my( $self, $fh, $host, $port, $id ) = @_;

	warn "data_sf_connected" if DEBUG;

	# kill the timeout timer
	$poe_kernel->delay( 'timeout_event' );

	# convert it into a readwrite wheel
	$self->data_rw( POE::Wheel::ReadWrite->new(
		Handle	=> $fh,
		Filter	=> POE::Filter::Stream->new,
		Driver	=> POE::Driver::SysRW->new,
		InputEvent	=> 'data_rw_input',
		ErrorEvent	=> 'data_rw_error',
		FlushedEvent	=> 'data_rw_flushed',
	) );

	# now, send the actual complex command :)
	my $cmd = $self->complex_command->{'cmd'};

	# do we need to translate the command?
	if ( exists $command_map{ $cmd } ) {
		$cmd = $command_map{ $cmd };
	} else {
		$cmd = uc( $cmd );
	}

	$self->command( 'complex_data', $cmd, $self->complex_command->{'args'} );

	return;
};

no MooseX::POE::SweetArgs;
__PACKAGE__->meta->make_immutable;
1;

=pod

=for stopwords ftp

=for Pod::Coverage command EOL START BUILD tell_master

=head1 SYNOPSIS

	# A simple FTP client logging in to a server

=head1 DESCRIPTION

This is a simple FTP client to use in a POE application. It's a complete rewrite of the old L<POE::Component::Client::FTP> codebase and
adds a lot of convenience functions. Most of the API is compatible, so you should have few problems porting your code to this module.

=head1 TLS support

TLS encryption is available if you want. You would need to enable the L</tls_cmd> and L</tls_data> attributes and have L<POE::Component::SSLify>
installed in order to use it. It will work with a lot of servers and commands. However, not the entire RFC is implemented! The relevant RFCs is
L<http://tools.ietf.org/html/rfc4217> and L<http://tools.ietf.org/html/rfc2228>. If you encounter problems when using TLS on a server, please
let me know by filing a bug report!

=cut
