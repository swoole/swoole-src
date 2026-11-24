--TEST--
swoole_socket_coro: empty kernel option values do not return uninitialized memory
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_not_linux();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

Swoole\Coroutine\run(static function () {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, SOL_TCP);
    foreach ([SO_TYPE, SO_RCVBUF, SO_SNDBUF] as $option) {
        Assert::integer($socket->getOption(SOL_SOCKET, $option));
        // Linux TCP_ULP (31) returns zero bytes when no upper layer protocol is installed.
        Assert::same($socket->getOption(SOL_TCP, 31), 0);
    }
    $socket->close();
});
echo "DONE\n";
?>
--EXPECT--
DONE
