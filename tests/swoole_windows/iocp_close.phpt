--TEST--
swoole_windows: close drains pending IOCP operations before releasing the socket
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_win();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Socket;

function listener(): Socket
{
    $socket = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($socket->bind('127.0.0.1', 0));
    Assert::true($socket->listen());
    return $socket;
}

function connection_pair(): array
{
    $server = listener();
    $connected = new Channel(1);
    Coroutine::create(function () use ($server, $connected) {
        $client = new Socket(AF_INET, SOCK_STREAM, 0);
        Assert::true($client->connect('127.0.0.1', $server->getsockname()['port']));
        $connected->push($client);
    });
    $peer = $server->accept(3);
    Assert::isInstanceOf($peer, Socket::class);
    $client = $connected->pop(3);
    Assert::isInstanceOf($client, Socket::class);
    $server->close();
    return [$client, $peer];
}

Coroutine\run(function () {
    $server = listener();
    $port = $server->getsockname()['port'];
    $acceptDone = false;
    Coroutine::create(function () use ($server, &$acceptDone) {
        Assert::false($server->accept(-1));
        $acceptDone = true;
    });
    $closed = new Channel(2);
    $closer = Coroutine::create(function () use ($server, $closed) {
        Assert::true($server->close());
        $closed->push(true);
    });
    // Neither cancellation completion nor a deferred close has run yet.
    Assert::false($server->isClosed());
    Coroutine::create(function () use ($server, $closed) {
        Assert::false($server->close());
        Assert::same($server->errCode, SOCKET_EBADF);
        $closed->push(false);
    });
    // The close barrier cannot abandon buffers still referenced by the kernel.
    Assert::false(Coroutine::cancel($closer));
    Assert::true($closed->pop(3));
    Assert::false($closed->pop(3));
    Assert::true($acceptDone);
    Assert::true($server->isClosed());
    Assert::false($server->close());
    $replacement = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($replacement->bind('127.0.0.1', $port));
    Assert::true($replacement->listen());
    $replacement->close();

    [$client, $peer] = connection_pair();
    Assert::true($client->setOption(SOL_SOCKET, SO_SNDBUF, 4096));
    $readDone = $writeDone = false;
    Coroutine::create(function () use ($client, &$readDone) {
        Assert::false($client->recv(1, -1));
        $readDone = true;
    });
    Coroutine::create(function () use ($client, &$writeDone) {
        $data = str_repeat('S', 256 * 1024);
        $sent = $client->sendAll($data, -1);
        // A native send completion may win the race with CancelIoEx.
        Assert::true($sent === false || ($sent >= 0 && $sent <= strlen($data)));
        $writeDone = true;
    });
    Assert::greaterThan($client->getBoundCid(SWOOLE_EVENT_READ), 0);
    Assert::greaterThan($client->getBoundCid(SWOOLE_EVENT_WRITE), 0);
    Assert::true($client->close());
    Assert::true($client->isClosed());
    Assert::true($readDone);
    Assert::true($writeDone);
    $peer->close();

    [$client, $peer] = connection_pair();
    Assert::true($client->setProtocol(['open_ssl' => true, 'ssl_verify_peer' => false]));
    // Closing must drain cancellation rather than wait for a new TLS read to time out.
    Assert::true($client->setOption(SOL_SOCKET, SO_RCVTIMEO, ['sec' => 30, 'usec' => 0]));
    $handshakeDone = false;
    Coroutine::create(function () use ($client, &$handshakeDone) {
        Assert::false($client->sslHandshake());
        $handshakeDone = true;
    });
    Assert::greaterThan($client->getBoundCid(SWOOLE_EVENT_READ), 0);
    Assert::greaterThan($client->getBoundCid(SWOOLE_EVENT_WRITE), 0);
    Assert::true($client->close());
    Assert::true($client->isClosed());
    Assert::true($handshakeDone);
    $peer->close();

    $stats = Coroutine::stats();
    Assert::same($stats['iocp_task_num'], 0);
    Assert::same($stats['iocp_blocking_task_num'], 0);
});

// The public close method also works outside a coroutine without prematurely
// freeing an AcceptEx OVERLAPPED structure or waiting for object destruction.
$server = listener();
$acceptDone = false;
Coroutine::create(function () use ($server, &$acceptDone) {
    Assert::false($server->accept(-1));
    $acceptDone = true;
});
Assert::true($server->close());
Assert::true($server->isClosed());
Assert::true($acceptDone);
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
