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
    $socket->sendto($peer['address'], $peer['port'], "server");
});

go(function () {
    $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP);
    $cli->sendto("127.0.0.1", 9502, "hello\n");
    $addr = null;
    $port = null;
    $cli->recvfrom(1024, $addr, $port);
    var_dump($addr, $port);
});
swoole_event::wait();
?>
--EXPECT--
hello
string(9) "127.0.0.1"
int(9502)
