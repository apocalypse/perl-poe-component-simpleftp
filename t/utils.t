#!/usr/bin/perl

use POE::Component::Client::SimpleFTP::Utils qw( :code mdtm_datetime );
use Test::More;

plan tests => 31 + 5 + 6;

# test the code_* subs
ok( ! code_preliminary( undef ), "undef is not preliminary" );
ok( ! code_preliminary( 'asdf' ), "non-digit is not preliminary" );
ok( ! code_preliminary( 0 ), "0 is not preliminary" );
ok( ! code_preliminary( 235235 ), "non-xxx is not preliminary" );
ok( ! code_preliminary( 500 ), "non-1xx is not preliminary" );
ok( code_preliminary( 110 ), "1xx is preliminary" );

ok( ! code_success( undef ), "undef is not success" );
ok( ! code_success( 'asdf' ), "non-digit is not success" );
ok( ! code_success( 0 ), "0 is not success" );
ok( ! code_success( 235235 ), "non-xxx is not success" );
ok( ! code_success( 500 ), "non-2xx is not success" );
ok( code_success( 257 ), "2xx is success" );

ok( ! code_intermediate( undef ), "undef is not intermediate" );
ok( ! code_intermediate( 'asdf' ), "non-digit is not intermediate" );
ok( ! code_intermediate( 0 ), "0 is not intermediate" );
ok( ! code_intermediate( 235235 ), "non-xxx is not intermediate" );
ok( ! code_intermediate( 500 ), "non-3xx is not intermediate" );
ok( code_intermediate( 310 ), "3xx is intermediate" );

ok( ! code_failure( undef ), "undef is not failure" );
ok( ! code_failure( 'asdf' ), "non-digit is not failure" );
ok( ! code_failure( 0 ), "0 is not failure" );
ok( ! code_failure( 235235 ), "non-xxx is not failure" );
ok( ! code_failure( 200 ), "non-4/5xx is not failure" );
ok( code_failure( 417 ), "4xx is failure" );
ok( code_failure( 503 ), "5xx is failure" );

ok( ! code_tls( undef ), "undef is not tls" );
ok( ! code_tls( 'asdf' ), "non-digit is not tls" );
ok( ! code_tls( 0 ), "0 is not tls" );
ok( ! code_tls( 235235 ), "non-xxx is not tls" );
ok( ! code_tls( 500 ), "non-6xx is not tls" );
ok( code_tls( 658 ), "6xx is tls" );

# test the mdtm_datetime parser
foreach my $bad ( qw( undef asdf 258sd 1359448 2345.234.234 ) ) {
	my $result = mdtm_datetime( $bad );
	ok( ! $result, "$bad is not valid MDTM" );
}
foreach my $good ( qw( 20110502230157 20110502230157.5 20110502230157.324524 ) ) {
	my $result = mdtm_datetime( $good );
	ok( defined $result, "$good is valid MDTM" );
	is( $result->epoch, 1304377317, "$good contains the right UNIX epoch" );
}
