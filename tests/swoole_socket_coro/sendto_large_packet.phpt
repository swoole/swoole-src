--TEST--
swoole_socket_coro: send large packet
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const N = 5;
//Server
go(function () {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
    $socket->bind('127.0.0.1', 9601);
    for ($i = 0; $i < N; $i++)
    {
        $peer = null;
        $data = $socket->recvfrom($peer);
        $socket->sendto($peer['address'], $peer['port'], "Swoole: $data");
        Assert::assert(strlen($data) >= 30000);
        Assert::assert(is_array($peer));
    }
});

//Client
go(function () {
    $socket = new  Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, 0);
    for ($i = 0; $i < N; $i++)
    {
        $socket->sendto('127.0.0.1', 9601, str_repeat('A', rand(30000, 65000)));
        $peer = null;
        $data = $socket->recvfrom($peer);
        Assert::assert(is_array($peer));
        Assert::assert(strlen($data) >= 30000);
    }
});
swoole_event_wait();
?>
--EXPECTF--
