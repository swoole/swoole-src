--TEST--
swoole_client_coro: sendto
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$port = get_one_free_port();

go(function () use ($port) {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
    $socket->bind('127.0.0.1', $port);
    $peer = null;
    echo $socket->recvfrom($peer);
    echo $socket->recvfrom($peer);
});

go(function () use ($port) {
    $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP);
    $cli->sendto('127.0.0.1', $port, "hello\n");
    $cli->sendto('localhost', $port, "hello\n");
});

swoole_event::wait();
?>
--EXPECT--
hello
hello
