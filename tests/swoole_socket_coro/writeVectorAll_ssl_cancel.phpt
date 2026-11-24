--TEST--
swoole_socket_coro: partial TLS vector writes preserve cancellation errors
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_client_request_body.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Socket;

Assert::setThrowException(true);
Coroutine::set(['log_level' => SWOOLE_LOG_WARNING]);
Coroutine\run(function () {
    $listener = http_client_body_listener(true);
    Assert::true($listener->setOption(SOL_SOCKET, SO_RCVBUF, 65536));
    $release = new Channel(1);
    $done = new Channel(1);
    $cid = Coroutine::getCid();
    Coroutine::create(function () use ($listener, $release, $done, $cid) {
        $peer = $listener->accept(5);
        Assert::notSame($peer, false);
        Assert::true($peer->sslHandshake());
        Assert::same($peer->recv(1, 5), 'H');
        // Allow completed partial writes to retire before cancelling the blocked write.
        Coroutine::sleep(0.01);
        Assert::true(Coroutine::cancel($cid));
        $release->pop();
        $peer->close();
        $done->push(true);
    });

    $socket = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($socket->setOption(SOL_SOCKET, SO_SNDBUF, 65536));
    Assert::true($socket->setProtocol(['open_ssl' => true]));
    Assert::true($socket->connect('127.0.0.1', $listener->getsockname()['port'], 5));
    $body = str_repeat('x', 16 * 1024 * 1024);
    $sent = $socket->writeVectorAll(['H', $body], 2);
    Assert::greaterThan($sent, 0);
    Assert::lessThan($sent, 1 + strlen($body));
    Assert::same($socket->errCode, SOCKET_ECANCELED);
    $socket->close();
    $release->close();
    Assert::true($done->pop(5));
    $listener->close();
});
echo "DONE\n";
?>
--EXPECT--
DONE
