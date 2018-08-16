--TEST--
swoole_client_coro: sendto
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

go(function () {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
    $socket->bind('127.0.0.1', 9502);
    $peer = null;
    echo $socket->recvfrom($peer);
});

go(function () {
    $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP);
    $cli->sendto("127.0.0.1", 9502, "hello\n");
});
swoole_event::wait();
?>
--EXPECT--
hello
