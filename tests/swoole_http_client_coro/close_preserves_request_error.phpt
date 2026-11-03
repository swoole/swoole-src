--TEST--
swoole_http_client_coro: repeated close preserves request errors (#6355)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function close_preserving_error(Swoole\Coroutine\Http\Client $client): void
{
    $error = [$client->statusCode, $client->errCode, $client->errMsg];
    Assert::notSame($client->errCode, 0);
    Assert::notEmpty($client->errMsg);
    for ($i = 0; $i < 2; $i++) {
        Assert::false($client->close());
        Assert::same([$client->statusCode, $client->errCode, $client->errMsg], $error);
    }
}

Swoole\Coroutine\run(function () {
    // A listening socket completes the TCP handshake but never sends an HTTP response.
    $server = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($server->bind('127.0.0.1', 0));
    Assert::true($server->listen());
    $port = $server->getsockname()['port'];
    foreach ([false, true] as $defer) {
        $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $port);
        $client->set(['timeout' => 0.05]);
        $client->setDefer($defer);
        if ($defer) {
            Assert::true($client->get('/'));
            Assert::false($client->recv());
        } else {
            Assert::false($client->get('/'));
        }
        Assert::same($client->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_REQUEST_TIMEOUT);
        Assert::same($client->errCode, SOCKET_ETIMEDOUT);
        close_preserving_error($client);
    }
    // Protocol errors must also survive explicit cleanup, rather than being replaced by a connection error.
    go(function () use ($server) {
        for ($i = 0; $i < 3; $i++) {
            $connection = $server->accept();
            $connection->recv();
            @$connection->send("INVALID RESPONSE\r\n\r\n");
            $connection->close();
        }
    });
    $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $port);
    $client->set(['timeout' => 2]);
    Assert::false($client->get('/'));
    Assert::same($client->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET);
    Assert::same($client->errCode, SWOOLE_ERROR_HTTP_INVALID_PROTOCOL);
    close_preserving_error($client);
    $server->close();
});
echo "DONE\n";
?>
--EXPECT--
DONE
