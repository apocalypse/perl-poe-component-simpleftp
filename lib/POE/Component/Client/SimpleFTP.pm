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
# * full TLS support - check the RFCs
# * FXP ( server<->server ) transfers
# * intelligent NAT detection
# * full ipv6 testing/support
# * restart/abort of a transfer
# * sending STAT while a complex command is in progress
# * manual control of PORT/PASV/TYPE - maybe unnecessary?
# RFC 959 commands:
# * REIN ( tricky to implement, as it messes with state )
# * STRU ( default file type is always a good idea )
# * MODE ( default stream type is always a good idea )
# * APPE ( should be easy to implement, but im lazy )
# * ALLO ( probably easy to implement, but it is generally unused? )
# * REST ( a bit tricky to implement, maybe later )
# * ABOR ( tricky to implement, as it messes with state )
# RFC 2228 commands:
# * AUTH ( only AUTH TLS is supported now )
# * PROT/PBSZ is supported with the default options
# * ADAT ( not needed for AUTH TLS? )
# * CCC ( not needed with TLS? )
# * MIC ( not needed with TLS? )
# * CONF ( not needed with TLS? )
# * ENC ( not needed with TLS? )
# RFC 2389 commands:
# * FEAT ( no formal parser but we can send the command )
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

{
	use Moose::Util::TypeConstraints;

	# it is valid until the next complex command, then we check this to see
	# what we need to do
	# A = ascii
	# I = image
	has data_type => (
		isa => enum( [ qw( A I ) ] ),
		is => 'rw',
		init_arg => undef,
		predicate => '_has_data_type',
	);
}

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

	warn "telling master about event $event\n" if DEBUG;

	$poe_kernel->post( $self->_master, $event, @args );
}

# the internal state of the connection
has state => (
	isa => 'Str',
	is => 'rw',
	default => 'connect',
	init_arg => undef,
	( DEBUG ? ( trigger => sub {
		my( $self, $new, $old ) = @_;
		warn "switching from state($old) to state($new)\n";
		return;
	} ) : () ),
);

# holds what "simple" command we are processing when state is 'simple_command'
has simple_command => (
	isa => 'Str',
	is => 'rw',
	init_arg => undef,
);

# holds whatever data the command needs
has command_data => (
	isa => 'Any',
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
	'disconnect'	=> "QUIT",
	'features'	=> "FEAT",
);

my @simple_commands = ( qw(
	cdup mdtm noop pwd site size stat syst help acct smnt
	cd cwd
	dele delete
	mkd mkdir
	rmd rmdir
	quot quote
	quit disconnect
	feat features
) );

my @complex_commands = ( qw(
	list ls
	nlst dir
	retr get
	stor stou put
) );

# build our "simple" command handlers
foreach my $cmd ( @simple_commands ) {
	event $cmd => sub {
		my( $self, @args ) = @_;
		my $command = $cmd;

		# ignore commands if we are shutting down
		return if $self->state eq 'shutdown';

		# are we already sending a command?
		if ( $self->state ne 'idle' ) {
			die "Unable to send '$cmd' because we are processing " . $self->state;
		}

		# do we need to translate the command to the actual FTP command?
		if ( exists $command_map{ $cmd } ) {
			$command = $command_map{ $cmd };
		}

		# store the command we are processing then send it
		warn "doing simple_command($cmd) with data(" . join( ' ', @args ) . ")\n" if DEBUG;
		$self->simple_command( $cmd );
		$self->command_data( \@args );
		$self->command( 'simple_command', $command, @args );
		return;
	};
}

# build our "complex" command handlers ( they require a data connection )
foreach my $cmd ( @complex_commands ) {
	event $cmd => sub {
		my( $self, @args ) = @_;

		# ignore commands if we are shutting down
		return if $self->state eq 'shutdown';

		# are we already sending a command?
		if ( $self->state ne 'idle' ) {
			die "Unable to send '$cmd' because we are processing " . $self->state;
		}

		# start doing this command!
		warn "doing complex command($cmd) with data(" . join( ' ', @args ) . ")\n" if DEBUG;
		$self->command_data( {
			'cmd' => $cmd,
			'data' => \@args,
		} );
		if ( $cmd =~ /^(?:ls|dir|list|nlst)$/ ) {
			$self->prepare_listing;
		} elsif ( $cmd =~ /^(?:get|put|retr|stor)$/ ) {
			$self->prepare_transfer;
		}

		return;
	};
}

# build our data complex command handlers
foreach my $cmd ( qw( put stor ) ) {
	event "${cmd}_data" => sub {
		my( $self, $input ) = @_;

		# don't print the input as it could be binary stuff
		warn "received ${cmd}_data\n" if DEBUG;

		# ignore commands if we are shutting down
		return if $self->state eq 'shutdown';

		# should only happen in complex state
		if ( $self->state eq 'complex_data' ) {
			# This should only happen for put commands
			if ( $self->command_data->{'cmd'} eq $cmd ) {
				# send the data to our rw wheel
				if ( defined $self->data_rw ) {
					$self->data_rw->put( $input );
				} else {
					die "got ${cmd}_data when we are not connected!";
				}
			} else {
				die "got ${cmd}_data when we are not doing a STOR";
			}
		} else {
			die "got ${cmd}_data when we are in wrong state: " . $self->state;
		}

		return;
	};

	event "${cmd}_close" => sub {
		my $self = shift;

		warn "received ${cmd}_close\n" if DEBUG;

		# ignore commands if we are shutting down
		return if $self->state eq 'shutdown';

		# should only happen in complex state
		if ( $self->state eq 'complex_data' ) {
			# This should only happen for put commands
			if ( $self->command_data->{'cmd'} eq $cmd ) {
				# kill the rw wheel, disconnecting from the server
				if ( defined $self->data_rw ) {
					$self->process_complex_closed;
				} else {
					# maybe a timing issue, server killed the connection while this event was in the queue?
					# then the data_rw_error event would have caught this and sent the appropriate error message
					warn "unable to ${cmd}_close as wheel is gone\n" if DEBUG;
				}
			} else {
				die "got ${cmd}_close when we are not doing a STOR";
			}
		} else {
			die "got ${cmd}_close when we are in wrong state: " . $self->state;
		}

		return;
	};
}

# rename support
event rename => sub {
	my( $self, $from, $to ) = @_;

	# ignore commands if we are shutting down
	return if $self->state eq 'shutdown';

	# are we already sending a command?
	if ( $self->state ne 'idle' ) {
		die "Unable to send 'rename' because we are processing " . $self->state;
	}

	# Start the rename!
	$self->command_data( {
		from => $from,
		to => $to,
	} );
	$self->command( 'rename_start', 'RNFR', $from );

	return;
};

sub _ftpd_rename_start {
	my( $self, $code, $reply ) = @_;

	if ( code_intermediate( $code ) ) {
		# TODO should we send a rename_partial event?
		$self->command( 'rename_done', 'RNTO', $self->command_data->{'to'} );
	} else {
		$self->tell_master( 'rename_error', $code, $reply, $self->command_data->{'from'}, $self->command_data->{'to'} );
		$self->command_data( undef );
		$self->state( 'idle' );
	}
}

sub _ftpd_rename_done {
	my( $self, $code, $reply ) = @_;

	my $event = 'rename';
	if ( ! code_success( $code ) ) {
		$event .= '_error';
	}
	$self->tell_master( $event, $code, $reply, $self->command_data->{'from'}, $self->command_data->{'to'} );

	$self->command_data( undef );
	$self->state( 'idle' );
}

sub prepare_listing {
	my $self = shift;

	# do we need to set the TYPE?
	if ( ! $self->_has_data_type or $self->data_type eq 'I' ) {
		$self->command_data->{'type'} = 'A';
		$self->command( 'complex_type', 'TYPE', 'A' );
	} else {
		# Okay, proceed to start the data connection stuff
		$self->start_data_connection;
	}
}

sub prepare_transfer {
	my $self = shift;

	# do we need to set the TYPE?
	if ( ! $self->_has_data_type or $self->data_type eq 'A' ) {
		$self->command_data->{'type'} = 'I';
		$self->command( 'complex_type', 'TYPE', 'I' );
	} else {
		# Okay, proceed to start the data connection stuff
		$self->start_data_connection;
	}
}

sub start_data_connection {
	my $self = shift;

	# okay, we go ahead with the PASV/PORT command
	if ( $self->connection_mode eq 'passive' ) {
		$self->command( 'complex_pasv', 'PASV' );
	} else {
		# Okay, create our listening socket
		$self->create_data_connection;
	}
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
			warn "Unable to use SSLify: $@\n";
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

	warn "starting\n" if DEBUG;

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
		$self->tell_master( 'connect_error', 0, 'timedout' );

		# nothing else to do...
		$self->_shutdown;
	} elsif ( $self->state eq 'complex_sf' ) {
		# timed out waiting for the data connection

		# since this is a pre-data-connection error, the complex command is done
		$self->process_complex_error( 0, 'timedout' );
		$self->state( 'idle' );
	} else {
		die "unknown state in timeout_event: " . $self->state;
	}

	return;
};

# shutdown the connection
sub _shutdown {
	my $self = shift;

	warn "shutdown\n" if DEBUG;
	$self->state( 'shutdown' );

	# destroy our wheels
	$self->cmd_sf( undef );
	$self->cmd_rw( undef );
	$self->data_sf( undef );
	$self->data_rw( undef );

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
	my( $self, $fh, $host, $port, $wheel_id ) = @_;

	warn "cmd_sf_connected\n" if DEBUG;

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
	my( $self, $operation, $errnum, $errstr, $wheel_id ) = @_;

	warn "cmd_sf_error $operation $errnum $errstr\n" if DEBUG;

	$self->tell_master( 'connect_error', 0, "$operation error $errnum: $errstr" );

	# nothing else to do...
	$self->_shutdown;

	return;
};

event cmd_rw_input => sub {
	my( $self, $input, $wheel_id ) = @_;

	warn "cmd_rw_input(" . $self->state . "): '$input'\n" if DEBUG;

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
			warn "begin of multi-line($code): '$string'\n" if DEBUG;
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
					warn "end of multi-line: '$string'\n" if DEBUG;
					$line = $self->input_buffer;
					$self->input_buffer( '' );
				}
			} else {
				warn "got entire line($code): '$string'\n" if DEBUG;
				$line = $string;
			}
		}
	} else {
		# If we are in a multi-line reply, just collect the input
		if ( length( $self->input_buffer ) ) {
			# per the RFC, the first character should be padded by a space if needed
			$input =~ s/^\s//;
			warn "got multi-line input: '$input'\n" if DEBUG;
			$self->input_buffer( $self->input_buffer . "\n" . $input );
			return;
		} else {
			die "ftpd sent invalid reply: $input";
		}
	}

	# process the input, depending on our state
	my $subref = "_ftpd_" . $self->state;
	warn "calling $subref to process $code:$line\n" if DEBUG;
	$self->$subref( $code, $line );

	return;
};

event cmd_rw_error => sub {
	my( $self, $operation, $errnum, $errstr, $wheel_id) = @_;

	warn "cmd_rw_error $operation $errnum $errstr\n" if DEBUG;

	$self->tell_master( 'connect_error', 0, "$operation error $errnum: $errstr" );

	# nothing else to do...
	$self->_shutdown;

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
	if ( $cmd eq 'QUOT' ) {
		# user-defined string, send it as-is!
		$cmd = shift @args;
	}

	$cmd = uc $cmd; # to make sure
	my $cmdstr = join( ' ', $cmd, @args );
	warn "sending command '$cmdstr'\n" if DEBUG;
	$self->cmd_rw->put( $cmdstr );
}

sub _ftpd_idle {
	my( $self, $code, $reply ) = @_;

	die "unexpected text while we are idle: $code $reply";
}

# should be the first line of text we received from the ftpd
sub _ftpd_connect {
	my( $self, $code, $reply ) = @_;

	# TODO should we parse the code for failure replies?

	$self->tell_master( 'connected', $code, $reply );

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
	my( $self, $code, $reply ) = @_;

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
		$self->tell_master( 'login_error', $code, $reply );
		$self->state( 'idle' );
	}
}

sub _ftpd_pbsz {
	my( $self, $code, $reply ) = @_;

	if ( code_success( $code ) ) {
		$self->command( 'prot', 'PROT', 'P' );
	} else {
		$self->tell_master( 'login_error', $code, $reply );
		$self->state( 'idle' );
	}
}

sub _ftpd_prot {
	my( $self, $code, $reply ) = @_;

	if ( code_success( $code ) ) {
		$self->tell_master( 'authenticated' );
	} else {
		$self->tell_master( 'login_error', $code, $reply );
	}

	$self->state( 'idle' );
}

sub _ftpd_user {
	my( $self, $code, $reply ) = @_;

	if ( code_success( $code ) ) {
		# no need for password ( probably anonymous account )
		$self->prepare_tls_stuff;
	} elsif ( code_intermediate( $code ) ) {
		# send the password!
		$self->command( 'password', 'PASS', $self->password );
	} else {
		$self->tell_master( 'login_error', $code, $reply );
		$self->state( 'idle' );
	}
}

sub prepare_tls_stuff {
	my $self = shift;

	# do we need to setup the data channel TLS stuff?
	if ( $self->tls_data ) {
		# TODO is 0 a good default?
		$self->command( 'pbsz', 'PBSZ', 0 );
	} else {
		$self->tell_master( 'authenticated' );
		$self->state( 'idle' );
	}
}

sub _ftpd_password {
	my( $self, $code, $reply ) = @_;

	if ( code_success( $code ) ) {
		$self->prepare_tls_stuff;
	} else {
		$self->tell_master( 'login_error', $code, $reply );
		$self->state( 'idle' );
	}
}

sub _ftpd_simple_command {
	my( $self, $code, $reply ) = @_;

	# special-case for quit
	if ( $self->simple_command =~ /^(?:quit|disconnect)$/ ) {
		$self->_shutdown;
		return;
	}

	my $event = $self->simple_command;
	if ( ! code_success( $code ) ) {
		$event .= '_error';
	}
	$self->tell_master( $event, $code, $reply, @{ $self->command_data } );

	$self->command_data( undef );
	$self->state( 'idle' );
}

sub _ftpd_complex_type {
	my( $self, $code, $reply ) = @_;

	if ( code_success( $code ) ) {
		$self->data_type( delete $self->command_data->{'type'} );
		$self->start_data_connection;
	} else {
		# since this is a pre-data-connection error, the complex command is done
		$self->process_complex_error( $code, $reply );
		$self->state( 'idle' );
	}
}

sub _ftpd_complex_pasv {
	my( $self, $code, $reply ) = @_;

	if ( code_success( $code ) ) {
		# Got the server's data!
		my @data = $reply =~ /(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)/;
		$self->command_data->{'ip'} = join '.', @data[0 .. 3];
		$self->command_data->{'port'} = $data[4]*256 + $data[5];

		# Okay, create our listening socket
		$self->create_data_connection;
	} else {
		# since this is a pre-data-connection error, the complex command is done
		$self->process_complex_error( $code, $reply );
		$self->state( 'idle' );
	}
}

sub _ftpd_complex_port {
	my( $self, $code, $reply ) = @_;

	if ( code_success( $code ) ) {
		# wait for the server to connect to us
		$self->state( 'complex_sf' );
	} else {
		# since this is a pre-data-connection error, the complex command is done
		$self->process_complex_error( $code, $reply );
		$self->state( 'idle' );
	}
}

sub create_data_connection {
	my $self = shift;

	# we now transition to the "complex" state
	# the "real" state is kept in $self->command_data->{cmd}

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
		$sf_args{ RemoteAddress } = $self->command_data->{'ip'};
		$sf_args{ RemotePort } = $self->command_data->{'port'};
	} else {
		# enable the Reuse param so we can sanely use the same local port
		$sf_args{ Reuse } = 1;
	}

	# create the socketfactory!
	$poe_kernel->delay( 'timeout_event' => $self->timeout );
	$self->data_sf( POE::Wheel::SocketFactory->new( %sf_args ) );

	# Now that we've created the SF, do we need to send the PORT data?
	if ( $self->connection_mode eq 'active' ) {
		# TODO what if SF had an error binding to the socket?
		my $socket = $self->data_sf->getsockname;
		my( $port, $addr ) = sockaddr_in( $socket );
		$addr = inet_ntoa( $addr );
		$addr = "127.0.0.1" if $addr eq "0.0.0.0";
		my @addr = split( /\./, $addr );
		my @port = ( int( $port / 256 ), $port % 256 );
		$self->command( 'complex_port', 'PORT', join( ',', @addr, @port ) );
	} else {
		# wait for the connection to server
		$self->state( 'complex_sf' );
	}
}

event data_sf_connected => sub {
	my( $self, $fh, $host, $port, $wheel_id ) = @_;

	warn "data_sf_connected\n" if DEBUG;

	# all done with the SF wheel
	$self->data_sf( undef );

	# kill the timeout timer
	$poe_kernel->delay( 'timeout_event' );

	# TODO prevent attacks by verifying that the connected IP actually is the same IP as the server we're connecting to?

	# args for the RW wheel
	my %rw_args = (
		Handle	=> $fh,
		Driver	=> POE::Driver::SysRW->new,
		InputEvent	=> 'data_rw_input',
		ErrorEvent	=> 'data_rw_error',
		FlushedEvent	=> 'data_rw_flushed',
	);
	if ( $self->command_data->{'cmd'} =~ /^(?:ls|dir|list|nlst)$/ ) {
		# TODO use POE::Filter::Ls or whatever?
		$rw_args{'Filter'} = POE::Filter::Line->new( InputLiteral => EOL );
	} else {
		$rw_args{'Filter'} = POE::Filter::Stream->new;
	}

	# convert it into a readwrite wheel
	$self->data_rw( POE::Wheel::ReadWrite->new( %rw_args ) );

	# now, send the actual complex command :)
	my $cmd = $self->command_data->{'cmd'};

	# do we need to translate the command?
	if ( exists $command_map{ $cmd } ) {
		$cmd = $command_map{ $cmd };
	} else {
		$cmd = uc( $cmd );
	}

	# since the code in sub command doesn't like sending undef's we have to check it here
	if ( defined $self->command_data->{'data'} ) {
		$self->command( 'complex_start', $cmd, @{ $self->command_data->{'data'} } );
	} else {
		$self->command( 'complex_start', $cmd );
	}

	return;
};

event data_sf_error => sub {
	my( $self, $operation, $errnum, $errstr, $wheel_id ) = @_;

	warn "data_sf_error: $operation $errnum $errstr\n" if DEBUG;

	# some sort of error?
	if ( $self->state eq 'complex_sf' ) {
		$self->process_complex_error( undef, "$operation error $errnum: $errstr" );
	} else {
		die "unexpected data_sf_error in wrong state: " . $self->state;
	}
};

sub _ftpd_complex_start {
	my( $self, $code, $reply ) = @_;

	# actually process the "start" of the command
	if ( code_preliminary( $code ) ) {
		# let the master know it's ready to send/receive stuff!
		$self->tell_master( $self->command_data->{'cmd'} . '_connected', @{ $self->command_data->{'data'} } );
		$self->state( 'complex_data' );

		# do we have any buffered data?
		if ( exists $self->command_data->{'buffer'} ) {
			warn "sending buffered chunks\n" if DEBUG;
			foreach my $chunk ( @{ $self->command_data->{'buffer'} } ) {
				$self->tell_master( $self->command_data->{'cmd'} . '_data', $chunk, @{ $self->command_data->{'data'} } );
			}
			delete $self->command_data->{'buffer'};
		}
	} elsif ( code_success( $code ) ) {
		die "unexpected success for start of complex command: $code $reply";
	} else {
		$self->process_complex_error( $code, $reply );
	}
}

sub _ftpd_complex_error {
	my( $self, $code, $reply ) = @_;

	# we are supposed to get some kind of error from the ftpd
	# because something screwed up while doing the data connection
	if ( code_failure( $code ) ) {
		# okay, all done!
		$self->state( 'idle' );
		$self->command_data( undef );
	} else {
		die "unexpected input while in complex_error state: $code $reply";
	}
}

sub _ftpd_complex_done {
	my( $self, $code, $reply ) = @_;

	# got the final result of the complex command!
	my $event = $self->command_data->{'cmd'};
	if ( ! code_success( $code ) ) {
		$event .= '_error';
	}
	$self->tell_master( $event, $code, $reply, @{ $self->command_data->{'data'} } );

	# clear all data for this complex command
	$self->state( 'idle' );
	$self->command_data( undef );

	# TODO maybe we got the complex reply *before* the RW is closed?
}

sub process_complex_error {
	my( $self, $code, $reply ) = @_;

	# go to the error state, so we can receive whatever the ftpd wants to send to us
	$self->state( 'complex_error' );

	$self->data_sf( undef );
	$self->data_rw( undef );

	$self->tell_master( $self->command_data->{'cmd'} . '_error', $code, $reply, @{ $self->command_data->{'data'} } );

	# all done processing this complex command
	$self->command_data( undef );
}

sub process_complex_closed {
	my $self = shift;

	# Okay, we are done with this command!
	$self->state( 'complex_done' );
	$self->data_rw( undef );

	# TODO should we send an event_closed command? I think it's superfluous...
}

event data_rw_input => sub {
	my( $self, $input, $wheel_id ) = @_;

	warn "data_rw_input: '$input'\n" if DEBUG;

	# should only happen in complex state
	if ( $self->state eq 'complex_data' ) {
		# send it back to the master
		$self->tell_master( $self->command_data->{'cmd'} . '_data', $input, @{ $self->command_data->{'data'} } );
	} elsif ( $self->state eq 'complex_start' ) {
		# oh boy, the server immediately sent us some data while we were processing the start
		# that means we have to buffer it so we correctly send it *after* we send the connected event
		warn "storing input for buffer\n" if DEBUG;
		if ( ! exists $self->command_data->{'buffer'} ) {
			$self->command_data->{'buffer'} = [ $input ];
		} else {
			push( @{ $self->command_data->{'buffer'} }, $input );
		}
	} else {
		die "unexpected data_rw_input in wrong state: " . $self->state;
	}

	return;
};

event data_rw_error => sub {
	my( $self, $operation, $errnum, $errstr, $wheel_id ) = @_;

	warn "data_rw_error: $operation $errnum $errstr\n" if DEBUG;

	# should only happen in complex state
	if ( $self->state eq 'complex_data' ) {
		# Is it a normal EOF or an error?
		if ( $operation eq "read" and $errnum == 0 ) {
			# only in the put state is this a real error
			if ( $self->command_data->{'cmd'} =~ /^(?:put|stor|stou)$/ ) {
				$self->process_complex_error( undef, "$operation error $errnum: $errstr" );
			} else {
				# otherwise it was a listing/get which means the data stream is done
				$self->process_complex_closed;
			}
		} else {
			$self->process_complex_error( undef, "$operation error $errnum: $errstr" );
		}
	} else {
		die "unexpected data_rw_error in wrong state: " . $self->state;
	}

	return;
};

event data_rw_flushed => sub {
	my( $self, $wheel_id ) = @_;

	warn "data_rw_flushed\n" if DEBUG;

	# should only happen in complex state
	if ( $self->state eq 'complex_data' ) {
		# This should only happen for put commands
		if ( $self->command_data->{'cmd'} =~ /^(?:put|stor|stou)$/ ) {
			$self->tell_master( $self->command_data->{'cmd'} . '_flushed', @{ $self->command_data->{'data'} } );
		} else {
			die "unexpected data_rw_flushed for complex command:" . $self->command_data->{'cmd'};
		}
	} else {
		die "unexpected data_rw_flushed in wrong state: " . $self->state;
	}

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
