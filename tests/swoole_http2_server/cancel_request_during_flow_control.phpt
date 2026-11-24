--TEST--
swoole_http2_server: deliver cancellation when a reset wakes a flow-control wait
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine\CanceledException;

$pm = new ProcessManager;
$pm->setWaitTimeout(5);
$pm->parentFunc = function () use ($pm) {
    $client = http2_test_open_request($pm->getFreePort(), '/');
    try {
        $data = http2_test_wait_for_frame($client, 0);
        Assert::same([$data['streamId'], $data['payload']], [1, 'A']);
        fwrite($client, http2_test_frame(3, 0, 1, pack('N', 8)) . http2_test_request_headers(3, '/'));
        $data = http2_test_wait_for_frame($client, 0);
        Assert::same([$data['streamId'], $data['payload']], [3, 'K']);
    } finally {
        fclose($client);
        $pm->kill();
    }
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'open_http2_protocol' => true,
        'http2_cancel_on_stream_reset' => true,
        'log_file' => '/dev/null',
    ]);
    $server->on('WorkerStart', fn () => $pm->wakeup());
    $server->on('Request', function ($request, $response) {
        if ($request->streamId === 1) {
            try {
                $response->end('AB');
                Assert::true(false, 'expected cancellation');
            } catch (CanceledException $e) {
                Assert::same($e->getReason()['code'], 8);
                Assert::false($response->isWritable());
                echo "flow-control wait canceled\n";
            }
        } else {
            Assert::true($response->end('K'));
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
flow-control wait canceled
