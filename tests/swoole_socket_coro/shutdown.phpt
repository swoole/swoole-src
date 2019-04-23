--TEST--
swoole_socket_coro: shutdown
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
for ($n = 2; $n--;) {
    $randoms[] = get_safe_random();
}
go(function () use ($randoms) {
    $server = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::assert($server->bind('127.0.0.1', 9601));
    Assert::assert($server->listen(512));
    $conn = $server->accept();
    Assert::assert($conn);
    Assert::isInstanceOf($conn, Swoole\Coroutine\Socket::class);
    Assert::eq($conn->recv(), array_shift($randoms));
    Assert::assert($conn->send(array_shift($randoms)) > 0);
    $conn->close();
    $server->close();
});
go(function () use ($randoms) {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::assert($socket->connect('127.0.0.1', 9601));
    Assert::assert($socket->send(array_shift($randoms)) > 0);
    Assert::eq($socket->recv(), array_shift($randoms));
    Assert::assert($socket->shutdown(STREAM_SHUT_WR));
    for ($n = MAX_REQUESTS; $n--;) {
        Assert::false($socket->send(array_shift($randoms)));
        Assert::eq($socket->errCode, SOCKET_EPIPE);
    }
    Assert::assert($socket->shutdown(STREAM_SHUT_RD));
    for ($n = MAX_REQUESTS; $n--;) {
        Assert::assert(!$socket->recv());
    }
    Assert::assert(!$socket->shutdown());
    Assert::eq($socket->errCode, SOCKET_ENOTCONN);
    Assert::assert($socket->close());
    Assert::assert(!$socket->send(''));
    Assert::assert(!$socket->recv());
    Assert::eq($socket->errCode, SOCKET_EBADF);
});
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
