--TEST--
swoole_windows: portable socket errno
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (stripos(PHP_OS, 'WIN') !== 0) {
    die('skip Windows only');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Coroutine\run(function () {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM);
    Assert::true($socket->bind('127.0.0.1', 0));
    Assert::true($socket->listen());
    Assert::false($socket->accept(0.01));
    Assert::same(SWOOLE_ERRNO_ETIMEDOUT, $socket->errCode);
    Assert::same(SWOOLE_ERRNO_ETIMEDOUT, swoole_last_error());
    Assert::same(SWOOLE_ERRNO_EAGAIN, SWOOLE_ERRNO_EWOULDBLOCK);

    if (extension_loaded('sockets')) {
        Assert::notSame(SOCKET_ETIMEDOUT, SWOOLE_ERRNO_ETIMEDOUT);
    }
});

echo "DONE\n";
?>
--EXPECT--
DONE
