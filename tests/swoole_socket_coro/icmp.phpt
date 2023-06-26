--TEST--
swoole_socket_coro: icmp
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Co\run(function () {
    /* ICMP ping packet with a pre-calculated checksum */
    $host = '127.0.0.1';
    $package = "\x08\x00\x7d\x4b\x00\x00\x00\x00PingHost";
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_RAW, 1);
    $socket->connect($host);
    $socket->send($package, strlen($package));
    $pkt = $socket->recv(256);
    Assert::notEmpty($pkt);
});
?>
--EXPECT--
