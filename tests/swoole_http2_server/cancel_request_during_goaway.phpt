--TEST--
swoole_http2_server: a canceled GOAWAY leaves the connection available to other streams
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
    $client = http2_test_open_request($pm->getFreePort(), '/', 0x7fffffff, 0x7fffffff, 65536);
    try {
        $pm->wait();
        fwrite($client, http2_test_request_headers(3, '/'));
        $pm->wait();
        fwrite($client, http2_test_frame(3, 0, 3, pack('N', 8))
            . http2_test_frame(3, 0, 1, pack('N', 8))
            . http2_test_request_headers(5, '/'));
        $pm->wait();

        while (true) {
            $frame = http2_test_read_frame($client);
            Assert::true($frame !== false);
            Assert::notSame($frame['type'], SWOOLE_HTTP2_TYPE_GOAWAY);
            if ($frame['type'] === SWOOLE_HTTP2_TYPE_SETTINGS && ($frame['flags'] & 1) === 0) {
                fwrite($client, http2_test_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 1, 0));
            }
            if ($frame['streamId'] === 5 && $frame['type'] === SWOOLE_HTTP2_TYPE_DATA) {
                Assert::same($frame['payload'], 'K');
                break;
            }
        }
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
        'socket_buffer_size' => 65536,
        'kernel_socket_send_buffer_size' => 4096,
    ]);
    $server->on('WorkerStart', fn () => $pm->wakeup());
    $server->on('Request', function ($request, $response) use ($pm, $server) {
        if ($request->streamId === 5) {
            Assert::true($response->end('K'));
            return;
        }
        try {
            if ($request->streamId === 1) {
                Event::defer(fn () => $pm->wakeup());
                $response->write(str_repeat('A', 16 * 1024 * 1024));
            } else {
                http2_test_fill_send_buffer($server, $request->fd);
                Event::defer(fn () => $pm->wakeup());
                $response->goaway(SWOOLE_HTTP2_ERROR_NO_ERROR);
            }
            Assert::true(false, 'expected cancellation');
        } catch (CanceledException $e) {
            Assert::same($e->getReason()['code'], 8);
            if ($request->streamId === 1) {
                $pm->wakeup();
            } else {
                echo "GOAWAY wait canceled\n";
            }
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
GOAWAY wait canceled
