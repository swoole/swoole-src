<?php
$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC); //异步非阻塞
echo "setHandler: connect\n";
$client->on("connect", function($cli) {
    echo "onConnect\n";
    $cli->send("hello world\n");
});
echo "setHandler: receive\n";
$client->on("receive", function($cli){
    $data = $cli->recv();
    //被服务器端关闭
    if(empty($data)){
        $cli->close();
        echo "client close\n";
    } else {
        echo "onReceive: $data\n";
        sleep(1);
        $cli->send("hello\n");
    }
});

$client->on("error", function($cli){
    echo "onError\n";
    exit;
});

echo "Connect to Server\n";
$client->connect('127.0.0.1', 9501, 0.5);
echo "OK\n";