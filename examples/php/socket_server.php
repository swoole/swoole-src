<?php
error_reporting(E_ALL);
$socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
if ( $socket === false ) {
    echo "socket_create() failed:reason:" . socket_strerror( socket_last_error() ) . "\n";
}
$ok = socket_bind( $socket,'127.0.0.1',11109);
if ( $ok === false ) {
    echo "socket_bind() failed:reason:" . socket_strerror( socket_last_error( $socket ) );
}

$ok = socket_listen($socket, 128);
if ( $ok === false ) {
    echo "socket_bind() failed:reason:" . socket_strerror( socket_last_error( $socket ) );
}

while ( true ) {
	sleep(1000);
    $conn = socket_accept($socket);
    if($conn) {
		if(socket_recv($conn, $data, 8192, null))
		{
			echo $data,"\n";
			socket_send($conn, "hello world\n", 11, null);
			socket_close($conn);
		}
	} else {
		echo "error\n";
	}
}
