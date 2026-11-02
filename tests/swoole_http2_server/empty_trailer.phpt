--TEST--
swoole_http2_server: end responses with an empty filtered trailer block
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
                foreach (['/body', '/streamed'] as $path) {
                    $request = new Swoole\Http2\Request;
                    $request->path = $path;
                    Assert::greaterThan($client->send($request), 0);
                    $response = $client->recv(2);
                    Assert::isInstanceOf($response, Swoole\Http2\Response::class);
                    Assert::same($response->data, 'body');
                }
                // Empty request DATA must still carry END_STREAM after pipeline writes share send_data().
                $request = new Swoole\Http2\Request;
                $request->path = '/body';
                $request->pipeline = true;
                $streamId = $client->send($request);
                Assert::greaterThan($streamId, 0);
                Assert::true($client->write($streamId, '', true));
                Assert::same($client->recv(2)->data, 'body');
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
            'log_file' => '/dev/null',
        ]);
        $server->on('WorkerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $server->on('Request', function ($request, $response) {
            $response->trailer = ['ignored' => null];
            if ($request->server['request_uri'] === '/streamed') {
                Assert::true($response->write('body'));
                Assert::true($response->end());
            } else {
                Assert::true($response->end('body'));
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
