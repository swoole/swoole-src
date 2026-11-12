--TEST--
swoole_http_client_coro: trim header value whitespace
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Coroutine\run(function () {
    $listener = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());
    $port = $listener->getsockname()['port'];

    $server = Swoole\Coroutine::create(function () use ($listener) {
        $connection = $listener->accept(2);
        Assert::notSame($connection, false);
        $request = '';
        while (!str_contains($request, "\r\n\r\n")) {
            $chunk = $connection->recv(4096, 2);
            Assert::notSame($chunk, false);
            Assert::notSame($chunk, '');
            $request .= $chunk;
        }
        $response =
            "HTTP/1.1 200 OK\r\nX-Whitespace: \talpha \t beta \t \r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        Assert::same($connection->sendAll($response), strlen($response));
        $connection->close();
    });

    $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $port);
    Assert::true($client->get('/'));
    Assert::same($client->headers['x-whitespace'], "alpha \t beta");
    $client->close();
    $listener->close();
    Swoole\Coroutine::join([$server]);
});
echo "DONE\n";
?>
--EXPECT--
DONE
