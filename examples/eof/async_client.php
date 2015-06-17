<?php
function send(swoole_client $cli)
{
    $_send = str_repeat('A', rand(10000, 50000)) . "\r\n\r\n";
    $cli->send($_send);
    echo "send ".strlen($_send)." bytes\n";
}

$client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC); //异步非阻塞
$client->set(array('open_eof_check' => true, 'package_eof' => "\r\n\r\n"));

$client->on("connect", function(swoole_client $cli) {
    send($cli);
});

$client->on("receive", function (swoole_client $cli, $data) {
    static $i = 0;
    if ($i % 100 == 1)
    {
        echo "received " . strlen($data) . " bytes\n";
    }
    $i ++;
    //usleep(200000);
    //send($cli);
});

$client->on("error", function(swoole_client $cli){
    echo "error\n";
});

$client->on("close", function(swoole_client $cli){
    echo "Connection close\n";
});

$client->connect('127.0.0.1', 9501);

