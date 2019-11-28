<?php
$n = empty($argv[1]) ? 1000 : intval($argv[1]);

Co\Run(function () use ($n) {
    $conns = [];
    while ($n--) {
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $client->connect('127.0.0.1', 9502);
        $conns[] = $client;
        echo "$n\n";
    }

    \Swoole\Coroutine\System::sleep(10000);
});