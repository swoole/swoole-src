<?php
ini_set("memory_limit", "1024m");

function reconn() {
    echo "Reconnect\n";
    $cli = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);
    $cli->on("connect", function(Swoole\Client $cli) {
        // client 发送 大包数据
        $cli->send(str_repeat("\0", 1024 * 1024 * 1.9));
    });
    $cli->on("receive", function(Swoole\Client $cli, $data) {
        $cli->send($data);
    });
    $cli->on("error", function(Swoole\Client $cli) { echo "error\n"; });
    $cli->on("close", function(Swoole\Client $cli) { echo "close\n"; reconn(); });
    $cli->connect('127.0.0.1', 9001);
}

reconn();
