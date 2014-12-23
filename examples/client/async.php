<?php
$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC); //异步非阻塞
$client->finish = false;
$client->_count = 0;
$client->on("connect", function(swoole_client $cli) {
    $cli->send("GET / HTTP/1.1\r\n\r\n");
    //$cli->sendfile(__DIR__.'/test.txt');
    //$cli->_count = 0;
});

$client->on("receive", function(swoole_client $cli, $data){
    echo "Receive: $data";
    $cli->_count++;
    if ($cli->_count > 10)
    {
        $cli->close();
        return;
    }
    $cli->send(str_repeat('A', 100)."\n");
    $cli->finish = true;
});

$client->on("error", function(swoole_client $cli){
    echo "error\n";
});

$client->on("close", function(swoole_client $cli){
    echo "Connection close\n";
});

$client->connect('127.0.0.1', 9502);
swoole_timer_after(1000, function () use ($client) {
    if ($client->finish) {
        return;
    } else {
        echo "socket timeout\n";
        $client->close();
    }
});

echo "connect to 127.0.0.1:9501\n";
//for PHP5.3-
//swoole_event_wait();
