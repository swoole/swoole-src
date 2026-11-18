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
        // Cut inside the UTF-8 sequence and between the last high byte and its trailing whitespace.
        $chunks = [
            "HTTP/1.1 200 OK\r\nX-Whitespace: \talpha \t beta \t \r\n",
            "X-Obs-80: alpha \t \x80\r\nX-Obs-80-Ows: alpha \t \x80",
            " \t\r\nX-Obs-Fe: alpha \t \xFE\r\nX-Obs-Fe-Ows: alpha \t \xFE \t\r\nX-Utf8: caf\xC3",
            "\xA9 \t caf\xC3\xA9\r\nX-Utf8-Ows: caf\xC3\xA9 \t caf\xC3",
            "\xA9 \t\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        ];
        foreach ($chunks as $chunk) {
            Assert::same($connection->sendAll($chunk), strlen($chunk));
            Swoole\Coroutine::sleep(0.01);
        }
        $connection->close();
    });

    $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $port);
    Assert::true($client->get('/'));
    Assert::same($client->headers['x-whitespace'], "alpha \t beta");
    $obsText = ['x-obs-80' => "alpha \t \x80", 'x-obs-fe' => "alpha \t \xFE", 'x-utf8' => "caf\xC3\xA9 \t caf\xC3\xA9"];
    foreach ($obsText as $name => $value) {
        Assert::same($client->headers[$name], $value);
        Assert::same($client->headers["{$name}-ows"], $value);
    }
    $client->close();
    $listener->close();
    Swoole\Coroutine::join([$server]);
});
echo "DONE\n";
?>
--EXPECT--
DONE
