--TEST--
swoole_socket_coro: recvAll shares one timeout across fragments
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Socket;

Assert::setThrowException(true);

Coroutine\run(function () {
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0) && $listener->listen());
    $port = $listener->getsockname()['port'];

    $sender = Coroutine::create(static function () use ($listener) {
        $peer = $listener->accept(2);
        Assert::true($peer instanceof Socket);
        Assert::same($peer->recvAll(1, 2), '!');
        Coroutine::sleep(0.1);
        Assert::same($peer->sendAll('A'), 1);
        Coroutine::sleep(0.2);
        Assert::same($peer->sendAll('B'), 1);
        $peer->close();
    });

    $client = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($client->connect('127.0.0.1', $port, 2));
    Assert::false($client->recvAll(1, 0.02));
    Assert::same($client->errCode, SOCKET_ETIMEDOUT);
    Assert::same($client->sendAll('!'), 1);
    // The 0.2s gap fits inside a fresh budget. The 0.3s total exceeds the call's budget.
    Assert::same($client->recvAll(2, 0.25), 'A');
    Assert::same($client->errCode, SOCKET_ETIMEDOUT);
    Assert::same($client->recvAll(1, 2), 'B');
    $client->close();
    Coroutine::join([$sender]);

    $listener->close();
});
echo "DONE\n";
?>
--EXPECT--
DONE
