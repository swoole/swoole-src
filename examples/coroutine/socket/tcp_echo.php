<?php
// Coroutine\Socket can be both server and client in one process.
// Run: php examples/coroutine/socket/tcp_echo.php
use Swoole\Coroutine\Socket;
use function Swoole\Coroutine\run;

run(function () {
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    $listener->bind('127.0.0.1', 0);
    $listener->listen();
    $port = $listener->getsockname()['port'];

    Swoole\Coroutine::create(function () use ($listener) {
        $conn = $listener->accept();
        $conn->send('echo: ' . $conn->recv(1024));
        $conn->close();
        $listener->close();
    });

    $client = new Socket(AF_INET, SOCK_STREAM, 0);
    $client->connect('127.0.0.1', $port);
    $client->send('hello');
    echo $client->recv(1024), PHP_EOL;
    $client->close();
});
