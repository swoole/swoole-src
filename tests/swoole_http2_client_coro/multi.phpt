--TEST--
swoole_http2_client_coro: multiplexed TLS requests preserve stream bodies and headers
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    try {
        Swoole\Coroutine\run(function () use ($pm) {
            $client = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort(), true);
            $client->set(['timeout' => 2]);
            Assert::true($client->connect());
            try {
                for ($i = 0; $i < 4; $i++) {
                    $request = new Swoole\Http2\Request;
                    $request->path = '/?id=' . $i;
                    $request->headers = ['host' => 'localhost', 'accept-encoding' => 'gzip'];
                    Assert::same($client->send($request), 2 * $i + 1);
                }
                $streams = [];
                $headerCounts = [];
                // A missing response must fail promptly, rather than polling indefinitely.
                for ($i = 0; $i < 4; $i++) {
                    $response = $client->recv(2);
                    if (!Assert::isInstanceOf($response, Swoole\Http2\Response::class)) {
                        break;
                    }
                    Assert::same($response->statusCode, 200);
                    $id = intdiv($response->streamId - 1, 2);
                    Assert::same($response->data, str_repeat("stream=$id\n", 128));
                    for ($n = 0; $n < 12; $n++) {
                        Assert::same($response->headers['x-test-' . $n], 'value-' . $n);
                    }
                    $streams[] = $response->streamId;
                    $headerCounts[] = count($response->headers);
                }
                sort($streams);
                Assert::same($streams, [1, 3, 5, 7]);
                Assert::same(count(array_unique($headerCounts)), 1);
            } finally {
                $client->close();
            }
        });
    } finally {
        $pm->kill();
    }
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    ]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $pending = [];
    $server->on('request', function ($request, $response) use (&$pending) {
        $pending[(int) $request->get['id']] = $response;
        if (count($pending) !== 4) {
            return;
        }
        // Complete all streams in reverse order on the same connection.
        for ($id = 3; $id >= 0; $id--) {
            $response = $pending[$id];
            for ($n = 0; $n < 12; $n++) {
                $response->header('x-test-' . $n, 'value-' . $n);
            }
            $response->end(str_repeat("stream=$id\n", 128));
        }
        $pending = [];
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
