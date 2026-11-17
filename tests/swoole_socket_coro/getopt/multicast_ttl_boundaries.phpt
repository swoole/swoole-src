--TEST--
swoole_socket_coro: multicast TTL values retain their unsigned byte range
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

Swoole\Coroutine\run(static function () {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_DGRAM, SOL_UDP);
    foreach ([0, 127, 128, 255] as $ttl) {
        Assert::true($socket->setOption(IPPROTO_IP, IP_MULTICAST_TTL, $ttl));
        Assert::same($socket->getOption(IPPROTO_IP, IP_MULTICAST_TTL), $ttl);
    }
    $socket->close();
});
echo "DONE\n";
?>
--EXPECT--
DONE
