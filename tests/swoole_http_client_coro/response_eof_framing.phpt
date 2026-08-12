--TEST--
swoole_http_client_coro: EOF only completes close-delimited responses
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        foreach (['/content-length', '/chunked'] as $path) {
            $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
            Assert::false($client->get($path));
            Assert::same($client->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET);
            Assert::same($client->errCode, SOCKET_ECONNRESET);
            Assert::false($client->connected);
        }

        $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->get('/close-delimited'));
        Assert::same($client->statusCode, 200);
        Assert::same($client->body, 'complete');

        $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->get('/exact'));
        Assert::same($client->statusCode, 200);
        Assert::same($client->body, 'exact');
        echo "DONE\n";
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['log_file' => '/dev/null']);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('receive', function (Swoole\Server $server, int $fd, int $reactorId, string $data) {
        if (str_contains($data, '/content-length')) {
            $response = "HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\nshort";
        } elseif (str_contains($data, '/chunked')) {
            $response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nabc";
        } elseif (str_contains($data, '/close-delimited')) {
            $response = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\ncomplete";
        } else {
            $response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nexact";
        }
        $server->send($fd, $response);
        $server->close($fd);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
