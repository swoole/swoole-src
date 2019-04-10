--TEST--
swoole_socket_coro: closed bad fd
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
    assert($socket->connect(REDIS_SERVER_HOST, REDIS_SERVER_PORT));
    assert($socket->close());
    Assert::eq($socket->errCode, 0);
    assert(!$socket->bind('127.0.0.1', 9501));
    Assert::eq($socket->errCode, SOCKET_EBADF);
    assert(!$socket->listen());
    Assert::eq($socket->errCode, SOCKET_EBADF);
    assert(!$socket->accept());
    Assert::eq($socket->errCode, SOCKET_EBADF);
    assert(!$socket->connect('127.0.0.1', 9501));
    Assert::eq($socket->errCode, SOCKET_EBADF);
    assert(!$socket->send(get_safe_random()));
    Assert::eq($socket->errCode, SOCKET_EBADF);
    assert(!$socket->recv());
    Assert::eq($socket->errCode, SOCKET_EBADF);
    assert(!$socket->sendto('127.0.0.1', 9501, get_safe_random()));
    Assert::eq($socket->errCode, SOCKET_EBADF);
    assert(!$socket->recvfrom($peer));
    Assert::eq($socket->errCode, SOCKET_EBADF);
    assert(!$socket->getsockname());
    Assert::eq($socket->errCode, SOCKET_EBADF);
    assert(!$socket->getpeername());
    Assert::eq($socket->errCode, SOCKET_EBADF);
    assert(!$socket->getSocket());
    Assert::eq($socket->errCode, SOCKET_EBADF);
    echo "DONE\n";
});
?>
--EXPECT--
DONE
