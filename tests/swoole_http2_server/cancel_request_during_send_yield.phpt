--TEST--
swoole_http2_server: cancel a DATA send under backpressure without breaking frame boundaries
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine\CanceledException;
use Swoole\Event;

$pm = new ProcessManager;
$pm->setWaitTimeout(5);
$pm->parentFunc = function () use ($pm) {
    // Do not read until the server has suspended on send_yield and processed the reset.
    $client = http2_test_open_request($pm->getFreePort(), '/', 0x7fffffff, 0x7fffffff);
    try {
        $pm->wait();
        fwrite($client, http2_test_frame(3, 0, 1, pack('N', 8)));
        $pm->wait();
        fwrite($client, http2_test_request_headers(3, '/'));
        // Parse every frame, including those already queued before the reset.
        $received = 0;
        do {
            $data = http2_test_wait_for_frame($client, 0);
            if ($data['streamId'] === 1) {
                Assert::same($data['payload'], str_repeat('A', strlen($data['payload'])));
                $received += strlen($data['payload']);
            } else {
                Assert::same([$data['streamId'], $data['payload']], [3, 'OK']);
            }
        } while ($data['streamId'] === 1);
        Assert::greaterThan($received, 0);
        Assert::lessThan($received, 16 * 1024 * 1024);
    } finally {
        fclose($client);
        $pm->kill();
    }
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'http2_cancel_on_stream_reset' => true,
        'http_compression' => false,
        'send_yield' => true,
        'buffer_output_size' => 1024 * 1024,
    ]);
    $server->on('WorkerStart', fn () => $pm->wakeup());
    $server->on('Request', function ($request, $response) use ($pm) {
        if ($request->streamId === 1) {
            Event::defer(fn () => $pm->wakeup());
            try {
                $response->write(str_repeat('A', 16 * 1024 * 1024));
                Assert::true(false, 'expected cancellation');
            } catch (CanceledException $e) {
                Assert::same($e->getReason()['code'], 8);
                Assert::false($response->isWritable());
                echo "send_yield canceled\n";
            }
            $pm->wakeup();
        } else {
            Assert::true($response->end('OK'));
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
send_yield canceled
