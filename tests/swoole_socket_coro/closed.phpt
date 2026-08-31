--TEST--
swoole_socket_coro: closed bad fd
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$server = stream_socket_server('tcp://127.0.0.1:0', $errorCode, $errorMessage);
Assert::assert($server !== false, $errorMessage ?: 'failed to create TCP server');
$serverAddress = stream_socket_get_name($server, false);
$port = (int) substr(strrchr($serverAddress, ':'), 1);

go(function () use ($port) {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
    Assert::assert($socket->connect('127.0.0.1', $port));
    Assert::assert($socket->close());
    Assert::same($socket->errCode, 0);
    Assert::assert(!$socket->bind('127.0.0.1', 9501));
    Assert::same($socket->errCode, SOCKET_EBADF);
    Assert::assert(!$socket->listen());
    Assert::same($socket->errCode, SOCKET_EBADF);
    Assert::assert(!$socket->accept());
    Assert::same($socket->errCode, SOCKET_EBADF);
    Assert::assert(!$socket->connect('127.0.0.1', 9501));
    Assert::same($socket->errCode, SOCKET_EBADF);
    Assert::assert(!$socket->send(get_safe_random()));
    Assert::same($socket->errCode, SOCKET_EBADF);
    Assert::assert(!$socket->recv());
    Assert::same($socket->errCode, SOCKET_EBADF);
    Assert::assert(!$socket->sendto('127.0.0.1', 9501, get_safe_random()));
    Assert::same($socket->errCode, SOCKET_EBADF);
    Assert::assert(!$socket->recvfrom($peer));
    Assert::same($socket->errCode, SOCKET_EBADF);
    Assert::assert(!$socket->getsockname());
    Assert::same($socket->errCode, SOCKET_EBADF);
    Assert::assert(!$socket->getpeername());
    Assert::same($socket->errCode, SOCKET_EBADF);
    echo "DONE\n";
});
fclose($server);
?>
--EXPECT--
DONE
