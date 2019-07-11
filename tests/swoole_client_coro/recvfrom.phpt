--TEST--
swoole_client_coro: sendto
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$free_port = get_one_free_port();

go(function () use ($free_port) {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
    $socket->bind('127.0.0.1', $free_port);
    $peer = null;
    echo $socket->recvfrom($peer);
    $socket->sendto($peer['address'], $peer['port'], "server");
});

go(function () use ($free_port) {
    $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP);
    $cli->sendto('127.0.0.1', $free_port, "hello\n");
    $addr = null;
    $port = null;
    $cli->recvfrom(1024, $addr, $port);
    Assert::same($addr, '127.0.0.1');
    Assert::same($port, $free_port);
});

swoole_event::wait();
?>
--EXPECT--
hello
