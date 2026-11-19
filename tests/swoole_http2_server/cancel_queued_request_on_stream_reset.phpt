--TEST--
swoole_http2_server: skip a reset request queued by worker_max_concurrency
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

$pm = new ProcessManager;
$pm->setWaitTimeout(5);
$pm->parentFunc = function () use ($pm) {
    $client = http2_test_open_request($pm->getFreePort(), '/');
    try {
        $data = http2_test_wait_for_frame($client, 0);
        Assert::same([$data['streamId'], $data['payload']], [1, 'O']);

        // Stream 1 holds the only slot until its stream window is updated.
        fwrite($client, http2_test_request_headers(3, '/')
            . http2_test_frame(3, 0, 3, pack('N', 8))
            . http2_test_frame(8, 0, 1, pack('N', 2)));
        $data = http2_test_wait_for_frame($client, 0);
        Assert::same([$data['streamId'], $data['payload']], [1, 'ne']);
        $data = http2_test_wait_for_frame($client, 0, 1);
        Assert::same([$data['streamId'], $data['payload']], [1, '']);

        fwrite($client, http2_test_request_headers(5, '/'));
        $data = http2_test_wait_for_frame($client, 0);
        Assert::same([$data['streamId'], $data['payload']], [5, 'K']);
        echo "DONE\n";
    } finally {
        fclose($client);
        $pm->kill();
    }
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'worker_max_concurrency' => 1,
        'open_http2_protocol' => true,
        'http2_cancel_on_stream_reset' => true,
        'log_file' => '/dev/null',
    ]);
    $server->on('WorkerStart', fn () => $pm->wakeup());
    $server->on('Request', function ($request, $response) {
        if ($request->streamId === 1) {
            Assert::true($response->write('One'));
            Assert::true($response->end());
        } else {
            Assert::same($request->streamId, 5);
            Assert::true($response->end('K'));
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
