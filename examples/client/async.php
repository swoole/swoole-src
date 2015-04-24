<?php
$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC); //异步非阻塞
$client->set(array('open_eof_check' => true, 'package_eof' => "\r\n\r\n"));
$client->_count = 0;
$client->on("connect", function(swoole_client $cli) {
    swoole_timer_clear($cli->timer);
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
});

$client->on("error", function(swoole_client $cli){
    echo "error\n";
});

$client->on("close", function(swoole_client $cli){
    echo "Connection close\n";
});

$client->connect('127.0.0.1', 9501);
$client->timer = swoole_timer_after(1000, function () use ($client) {
    echo "socket timeout\n";
    $client->close();
});

echo "connect to 127.0.0.1:9501\n";
//for PHP5.3-
//swoole_event_wait();
