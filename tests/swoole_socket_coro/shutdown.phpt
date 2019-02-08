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
    assert($server->bind('127.0.0.1', 9601));
    assert($server->listen(512));
    $conn = $server->accept();
    assert($conn);
    assert($conn instanceof Swoole\Coroutine\Socket);
    assert($conn->recv() === array_shift($randoms));
    assert($conn->send(array_shift($randoms)) > 0);
    $conn->close();
    $server->close();
});
go(function () use ($randoms) {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    assert($socket->connect('127.0.0.1', 9601));
    assert($socket->send(array_shift($randoms)) > 0);
    assert($socket->recv() === array_shift($randoms));
    assert($socket->shutdown(STREAM_SHUT_WR));
    for ($n = MAX_REQUESTS; $n--;) {
        assert($socket->send(array_shift($randoms)) === false);
        assert($socket->errCode === SOCKET_EPIPE);
    }
    assert($socket->shutdown(STREAM_SHUT_RD));
    for ($n = MAX_REQUESTS; $n--;) {
        assert(!$socket->recv());
    }
    assert(!$socket->shutdown());
    assert($socket->errCode === SOCKET_ENOTCONN);
    assert($socket->close());
    assert(!$socket->send(''));
    assert(!$socket->recv());
    assert($socket->errCode === SOCKET_EBADF);
});
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
