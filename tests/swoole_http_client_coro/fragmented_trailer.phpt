--TEST--
swoole_http_client_coro: parse fragmented trailer fields and values
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->get('/'));
        Assert::same($client->statusCode, 200);
        Assert::same($client->body, 'body');
        Assert::same($client->headers['x-before'], 'intact');
        Assert::same($client->headers['x-trailer'], 'fragmented-value');

        $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        Assert::false($client->get('/oversized'));
        Assert::same($client->errCode, SWOOLE_ERROR_HTTP_INVALID_PROTOCOL);
        Assert::same($client->errMsg, 'HTTP/1 header block is too large');
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'log_file' => '/dev/null',
        'open_http_protocol' => true,
    ]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('receive', function (Swoole\Server $server, int $fd, int $reactorId, string $data) {
        if (str_starts_with($data, 'GET /oversized ')) {
            $response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trailer\r\n\r\n0\r\nX-Trailer: ";
            $response .= str_repeat('A', 65536) . "\r\n\r\n";
            $server->send($fd, $response);
            return;
        }
        $server->send($fd, "HTTP/1.1 200 OK\r\nX-Before: intact\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trailer\r\n\r\n4\r\nbody\r\n0\r\nX-Tra");
        Swoole\Timer::after(10, function () use ($server, $fd) {
            $server->send($fd, "iler: fragmented-");
            Swoole\Timer::after(10, function () use ($server, $fd) {
                $server->send($fd, "value\r\n\r\n");
            });
        });
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
