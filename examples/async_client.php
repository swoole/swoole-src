<?php
$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC); //异步非阻塞

$client->on("connect", function($cli) {
    $cli->send("hello world\n");
});

$client->on("receive", function($cli){
    $data = $cli->recv();
    //被服务器端关闭
    if(empty($data)){
        $cli->close();
        echo "closed\n";
    } else {
        echo "received: $data\n";
        sleep(100);
        exit;
        $cli->send("hello\n");
    }
});

$client->on("error", function($cli){
    exit("error\n");
});

$client->on("close", function($cli){
    exit("close\n");
});

$client->connect('127.0.0.1', 9501, 0.5);


