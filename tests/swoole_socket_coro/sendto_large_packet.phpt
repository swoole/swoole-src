--TEST--
swoole_socket_coro: send large packet
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Socket;
use Swoole\Event;

const N = 5;
const MIN_PACKET_SIZE = IS_MAC_OS ? 4000 : 30000;
const MAX_PACKET_SIZE = IS_MAC_OS ? 8000 : 65000;

// Server
go(function () {
    $socket = new Socket(AF_INET, SOCK_DGRAM, 0);
    $socket->bind('127.0.0.1', 9601);
    for ($i = 0; $i < N; $i++) {
        $peer = null;
        $data = $socket->recvfrom($peer);
        Assert::assert($data);
        Assert::assert($socket->sendto($peer['address'], $peer['port'], "Swoole: {$data}"));
        Assert::assert(strlen($data) >= MIN_PACKET_SIZE);
        Assert::assert(is_array($peer));
    }
});

// Client
go(function () {
    $socket = new Socket(AF_INET, SOCK_DGRAM, 0);
    for ($i = 0; $i < N; $i++) {
        Assert::assert($socket->sendto('127.0.0.1', 9601, str_repeat('A', rand(MIN_PACKET_SIZE, MAX_PACKET_SIZE))), 'error: ' . swoole_strerror($socket->errCode));
        $peer = null;
        $data = $socket->recvfrom($peer);
        Assert::assert($data);
        Assert::assert(is_array($peer));
        Assert::assert(strlen($data) >= MIN_PACKET_SIZE);
    }
});
Event::wait();
?>
--EXPECTF--
