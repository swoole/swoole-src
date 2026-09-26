--TEST--
swoole_windows: coroutine socket error domain
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (stripos(PHP_OS, 'WIN') !== 0) {
    die('skip Windows only');
}
if (!class_exists(Swoole\Coroutine\Socket::class, false)) {
    die('skip coroutine socket not available');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Socket;

use function Swoole\Coroutine\run;

run(function () {
    $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::false($socket->getpeername());
    Assert::same($socket->errCode, SOCKET_ENOTCONN);

    $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::false($socket->listen());
    Assert::same($socket->errCode, SOCKET_EINVAL);

    $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::true($socket->bind('127.0.0.1', 0));
    Assert::false($socket->bind('127.0.0.1', 0));
    Assert::same($socket->errCode, SOCKET_EINVAL);

    $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::false($socket->peek());
    Assert::same($socket->errCode, SOCKET_ENOTCONN);

    $socket = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::false($socket->checkLiveness());
    Assert::same($socket->errCode, SOCKET_ENOTCONN);
});

echo "DONE\n";
?>
--EXPECT--
DONE
