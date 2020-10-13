<?php

Co\run(
    function () {
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP | SWOOLE_SSL);
        echo "connect\n";
        $client->connect("127.0.0.1", 9905);
        echo "connect OK\n";
        $client->send("hello world");
        echo $client->recv();
        $client->close();
        echo "END\n";
    }
);