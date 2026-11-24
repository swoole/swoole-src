<?php
// Coroutine\Client is a simple TCP client. Start examples/server/port.php
// (it echoes on 127.0.0.1:9506) first, then run this.
// Run: php examples/client/coro_echo.php
use Swoole\Coroutine\Client;
use function Swoole\Coroutine\run;

run(function () {
    $client = new Client(SWOOLE_SOCK_TCP);
    if (!$client->connect('127.0.0.1', 9506, 1)) {
        echo 'start examples/server/port.php first' . PHP_EOL;
        return;
    }
    $client->send('hello');
    echo $client->recv(), PHP_EOL;
    $client->close();
});
