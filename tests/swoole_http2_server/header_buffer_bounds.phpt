--TEST--
swoole_http2_server: grow header buffers while preserving legacy large-header exchanges
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $pm = new ProcessManager;
    $pm->parentFunc = function () use ($pm) {
        try {
            Swoole\Coroutine\run(function () use ($pm) {
                $client = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
                Assert::true($client->connect());

                $request = new Swoole\Http2\Request;
                $request->path = '/large';
                for ($i = 0; $i < 4; ++$i) {
                    $request->headers['x-large-' . $i] = str_repeat('0', 50000);
                }
                $request->cookies = ['token' => 'value'];
                // These branches historically accept header frames above the default peer limit.
                Assert::greaterThan($client->send($request), 0);
                $response = $client->recv(2);
                if ($response === false) {
                    throw new RuntimeException($client->errCode . ': ' . $client->errMsg);
                }
                Assert::same($response->data, 'large');
                Assert::same($response->headers['x-header'], str_repeat('1', 40000));
                Assert::same($response->headers['x-trailer'], str_repeat('2', 40000));
                Assert::true($client->connected);

                // Ensure the HPACK tables are still synchronized after the large blocks.
                $request = new Swoole\Http2\Request;
                $request->path = '/next';
                Assert::greaterThan($client->send($request), 0);
                Assert::same($client->recv(2)->data, 'next');
                Assert::true($client->connected);
                $client->close();
            });
        } finally {
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set([
            'worker_num' => 1,
            'reactor_num' => 1,
            'open_http2_protocol' => true,
            'http_compression' => false,
            'log_file' => '/dev/null',
        ]);
        $server->on('WorkerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $server->on('Request', function ($request, $response) {
            if ($request->server['request_uri'] === '/large') {
                for ($i = 0; $i < 4; ++$i) {
                    Assert::same($request->header['x-large-' . $i], str_repeat('0', 50000));
                }
                Assert::same($request->cookie['token'], 'value');
                $response->header('x-header', str_repeat('1', 40000));
                $response->trailer('x-trailer', str_repeat('2', 40000));
                Assert::true($response->end('large'));
            } else {
                Assert::true($response->end('next'));
            }
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
