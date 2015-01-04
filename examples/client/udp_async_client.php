<?php
$client = new swoole_client(SWOOLE_SOCK_UDP, SWOOLE_SOCK_ASYNC); //异步非阻塞

$client->on("connect", function(swoole_client $cli) {
    echo "connected\n";
    $cli->send("hello world\n");
});

$client->on('close', function($cli){
    echo "closed\n";
});

$client->on('error', function($cli){
    echo "error\n";
});

$client->on("receive", function(swoole_client $cli, $data){
	echo "received: $data\n";
	sleep(1);
	$cli->send("hello_".rand(1000,9999));
});

$client->connect('127.0.0.1', 9502, 0.5);
