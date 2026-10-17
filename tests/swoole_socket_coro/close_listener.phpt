--TEST--
swoole_socket_coro: release a listening socket when it is closed
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Socket;

function create_listener(int $port = 0): Socket
{
    $socket = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($socket->bind('127.0.0.1', $port));
    Assert::true($socket->listen());
    return $socket;
}

function listen_again(int $port): void
{
    $socket = create_listener($port);
    Coroutine::sleep(0.01);
    $client = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($client->connect('127.0.0.1', $port));
    Assert::isInstanceOf($socket->accept(1), Socket::class);
}

Coroutine\run(function () {
    $socket = create_listener();
    $port = $socket->getsockname()['port'];
    Assert::true($socket->close());
    listen_again($port);

    $socket = create_listener();
    $port = $socket->getsockname()['port'];
    Coroutine::create(function () use ($socket) {
        Assert::false($socket->accept(1));
    });
    Assert::true($socket->close());
    Assert::true($socket->isClosed());
    listen_again($port);

    $socket = create_listener();
    $port = $socket->getsockname()['port'];
    Coroutine::create(function () use ($socket) {
        Assert::false($socket->accept(1));
        Assert::true($socket->close());
    });
    Assert::true($socket->close());
    Assert::true($socket->isClosed());
    listen_again($port);
});
echo "DONE\n";
?>
--EXPECT--
DONE
