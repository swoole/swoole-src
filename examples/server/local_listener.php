<?php
$serv = new Swoole\Server("0.0.0.0", 9502);

$serv->on('workerstart', function($server, $id) {
     global $argv;
     swoole_set_process_name("php {$argv[0]}: worker");

     $local_listener = stream_socket_server("127.0.0.1", 9999);

     Swoole\Event::add($local_listener, function($server){
		  $local_client = stream_socket_accept($server);

		  Swoole\Event::add($local_client, function($client){
			  echo fread($client, 8192);
			  fwrite($client, "hello");
		  });
     });

});

$serv->on('connect', function (Swoole\Server $serv, $fd, $reactor_id) {
	//echo "connect\n";;
});

$serv->on('receive', function (Swoole\Server $serv, $fd, $reactor_id, $data) {
	$serv->send($fd, "Swoole: ".$data);
	//$serv->close($fd);
});

$serv->on('close', function (Swoole\Server $serv, $fd, $reactor_id) {
	//var_dump($serv->connection_info($fd));
	//echo "onClose\n";
});

$serv->start();
