<?php
$client = new swoole_client(SWOOLE_SOCK_UDP, SWOOLE_SOCK_SYNC); //同步阻塞
$client->connect('127.0.0.1', 9501, 0.5, 0);
$mem_start = memory_get_peak_usage();
for($i=0; $i< 1; $i++){
    $client->send("hello world-{$i}");
    $data = $client->recv(1024, 0);
}
echo "Mem User=".(memory_get_peak_usage() - $mem_start)."\n";
$client->close();
/*
$client = new swoole_client(SW_SOCK_TCP, SW_SOCK_ASYNC); //异步非阻塞
$client->connect('127.0.0.1', 9501, 0.5, 0);

$client->on("connect", function($cli){
    $cli->send("hello world\n");
    echo "onConnect";
});

$client->on("receive", function($cli, $data){
    echo "onReceive: $data\n";
});

$client->on("close", function($cli){
    echo "onClose: $data\n";
});
*/