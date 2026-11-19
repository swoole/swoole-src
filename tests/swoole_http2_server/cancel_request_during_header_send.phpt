--TEST--
swoole_http2_server: preserve the order of queued HEADERS when the peer resets a stream
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
    $client = http2_test_open_request($pm->getFreePort(), '/', 0x7fffffff);
    try {
        $pm->wait();
        fwrite($client, http2_test_request_headers(3, '/'));
        $pm->wait();
        fwrite($client, http2_test_request_headers(5, '/'));
        $pm->wait();
        fwrite($client, http2_test_frame(3, 0, 3, pack('N', 8))
            . http2_test_frame(3, 0, 1, pack('N', 8)));
        // Stream 1 wakes us after the worker has processed both resets.
        $pm->wait();

        // Stream 3's HEADERS must reach the peer before the later block for stream 5.
        $headerStreams = [];
        while (true) {
            $frame = http2_test_read_frame($client);
            Assert::true($frame !== false);
            if ($frame['type'] === 4 && ($frame['flags'] & 1) === 0) {
                fwrite($client, http2_test_frame(4, 1, 0));
            }
            if ($frame['streamId'] === 3 || ($frame['streamId'] === 5 && $frame['type'] === SWOOLE_HTTP2_TYPE_HEADERS)) {
                Assert::same($frame['type'], SWOOLE_HTTP2_TYPE_HEADERS);
                $headerStreams[] = $frame['streamId'];
            }
            if ($frame['streamId'] === 5 && $frame['type'] === SWOOLE_HTTP2_TYPE_DATA) {
                Assert::same($frame['payload'], 'K');
                break;
            }
        }
        Assert::same($headerStreams, [3, 5]);
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
        // The parent keeps the receive buffer full until every writer is waiting.
        Event::defer(fn () => $pm->wakeup());
        if ($request->streamId === 5) {
            Assert::true($response->end('K'));
            return;
        }
        try {
            $response->write($request->streamId === 1 ? str_repeat('A', 16 * 1024 * 1024) : 'B');
            Assert::true(false, 'expected cancellation');
        } catch (CanceledException $e) {
            Assert::same($e->getReason()['code'], 8);
            if ($request->streamId === 1) {
                $pm->wakeup();
            } else {
                echo "header wait canceled\n";
            }
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
header wait canceled
