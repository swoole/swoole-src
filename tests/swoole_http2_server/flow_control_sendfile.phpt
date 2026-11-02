--TEST--
swoole_http2_server: sendfile returns false when a flow-control wait ends with its stream
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

$file = tempnam(sys_get_temp_dir(), 'swoole_http2_flow_');
file_put_contents($file, str_repeat('A', 1024));

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    foreach (['reset', 'close'] as $termination) {
        $pm = new ProcessManager;
        $pm->setWaitTimeout(3);
        $pm->parentFunc = function () use ($pm, $termination) {
            $client = http2_test_open_request($pm->getFreePort(), '/');
            $data = http2_test_wait_for_frame($client, 0);
            Assert::same($data['payload'], 'A');

            if ($termination === 'reset') {
                fwrite($client, http2_test_frame(3, 0, 1, pack('N', 8)));
            } else {
                fclose($client);
            }
            Assert::true($pm->wait());

            if ($termination === 'reset') {
                // A stream-level failure must leave other requests on this connection usable.
                fwrite($client, http2_test_request_headers(3, '/health'));
                $data = http2_test_wait_for_frame($client, 0);
                Assert::same($data['streamId'], 3);
                Assert::same($data['payload'], 'K');
                fclose($client);
            }
            $pm->kill();
        };
        $pm->childFunc = function () use ($pm, $mode, $file) {
            $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
            $server->set([
                'worker_num' => 1,
                'log_file' => '/dev/null',
                'open_http2_protocol' => true,
            ]);
            $server->on('WorkerStart', function () use ($pm) {
                $pm->wakeup();
            });
            $server->on('Request', function ($request, $response) use ($pm, $file) {
                if ($request->server['request_uri'] === '/health') {
                    $response->end('K');
                    return;
                }
                var_dump($response->sendfile($file));
                Assert::false($response->isWritable());
                $pm->wakeup();
            });
            $server->start();
        };
        $pm->childFirst();
        $pm->run();
    }
}
unlink($file);
?>
--EXPECT--
bool(false)
bool(false)
bool(false)
bool(false)
