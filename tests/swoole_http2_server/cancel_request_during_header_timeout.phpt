--TEST--
swoole_http2_server: a reset HEADERS write can time out without escaping the request catch
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine\CanceledException;
use Swoole\Event;

$pm = new ProcessManager;
$pm->setWaitTimeout(6);
$pm->parentFunc = function () use ($pm) {
    $client = http2_test_open_request($pm->getFreePort(), '/', 0x7fffffff, 0x7fffffff);
    try {
        $pm->wait();
        fwrite($client, http2_test_request_headers(3, '/'));
        $pm->wait();
        fwrite($client, http2_test_frame(3, 0, 3, pack('N', 8))
            . http2_test_frame(3, 0, 1, pack('N', 8)));
        // Keep the buffer full until the reset request catches cancellation after the timeout.
        $pm->wait();
        while (($data = fread($client, 8192)) !== false && $data !== '') {
        }
        Assert::true(feof($client));
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
        'send_timeout' => 2,
        'buffer_output_size' => 1024 * 1024,
    ]);
    $server->on('WorkerStart', fn () => $pm->wakeup());
    $server->on('Close', fn () => print("connection closed\n"));
    $server->on('Request', function ($request, $response) use ($pm) {
        Event::defer(fn () => $pm->wakeup());
        try {
            $response->write($request->streamId === 1 ? str_repeat('A', 16 * 1024 * 1024) : 'B');
            Assert::true(false, 'expected cancellation');
        } catch (CanceledException $e) {
            Assert::same($e->getReason()['code'], 8);
            if ($request->streamId === 3) {
                echo "request caught cancellation\n";
                $pm->wakeup();
            }
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
request caught cancellation
connection closed
