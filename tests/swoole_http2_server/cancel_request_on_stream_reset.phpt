--TEST--
swoole_http2_server: opt-in request coroutine cancellation on peer reset
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine;
use Swoole\Coroutine\CanceledException;
use Swoole\Coroutine\Channel;
use Swoole\Event;

foreach ([[SWOOLE_BASE, false], [SWOOLE_BASE, true], [SWOOLE_PROCESS, true]] as [$mode, $enabled]) {
    $pm = new ProcessManager;
    $pm->setWaitTimeout(5);
    $pm->parentFunc = function () use ($pm, $enabled) {
        $client = http2_test_open_request($pm->getFreePort(), '/', 65535);
        try {
            $pm->wait();
            $reset = http2_test_frame(3, 0, 1, pack('N', 8));
            fwrite($client, $reset . $reset . http2_test_request_headers(3, '/'));
            $data = http2_test_wait_for_frame($client, 0);
            Assert::same([$data['streamId'], $data['payload']], [3, 'OK']);
            if ($enabled) {
                fwrite($client, http2_test_frame(3, 0, 3, pack('N', 8)) . http2_test_request_headers(5, '/'));
                $data = http2_test_wait_for_frame($client, 0);
                Assert::same([$data['streamId'], $data['payload']], [5, 'K']);

                // Stream 7 still has an open response, but only its coroutine defer is running.
                fwrite($client, http2_test_request_headers(7, '/'));
                $pm->wait();
                fwrite($client, http2_test_frame(3, 0, 7, pack('N', 8)) . http2_test_request_headers(9, '/'));
                $data = http2_test_wait_for_frame($client, 0);
                Assert::same([$data['streamId'], $data['payload']], [9, 'K']);
            }
        } finally {
            fclose($client);
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode, $enabled) {
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $settings = [
            'worker_num' => 1,
            'open_http2_protocol' => true,
            'log_file' => '/dev/null',
        ];
        if ($enabled) {
            $settings['http2_cancel_on_stream_reset'] = true;
        }
        $server->set($settings);
        $release = new Channel(1);
        $finished = [];
        $server->on('WorkerStart', fn () => $pm->wakeup());
        $server->on('Request', function ($request, $response) use ($pm, $enabled, $release, &$finished) {
            if ($request->streamId === 1) {
                $pm->wakeup();
                try {
                    Assert::true($release->pop(5));
                    Assert::false($enabled);
                    Assert::false($response->isWritable());
                    echo "default: request continued\n";
                } catch (CanceledException $e) {
                    Assert::true($enabled);
                    Assert::same($e->getReason(), [
                        'session_id' => $request->fd,
                        'stream_id' => $request->streamId,
                        'code' => 8,
                        'message' => 'HTTP2 Stream Reset',
                    ]);
                    Assert::false($response->isWritable());
                    Assert::false($response->write('x'));
                    echo "request canceled\n";
                } finally {
                    $finished[] = 1;
                }
            } elseif ($enabled && $request->streamId === 3) {
                Assert::same($finished, [1]);
                Assert::true($response->end('OK'));
                Assert::true($release->pop(5));
                $finished[] = 3;
                echo "finished response: request continued\n";
            } elseif ($enabled && $request->streamId === 7) {
                // Yield in the callback so the stream already has this coroutine's CID.
                $firstYield = new Channel(1);
                Event::defer(fn () => $firstYield->push(true));
                Assert::true($firstYield->pop(5));
                Coroutine::defer(function () use ($pm, $release, $response, &$finished) {
                    $pm->wakeup();
                    Assert::true($release->pop(5));
                    Assert::false($response->isWritable());
                    $finished[] = 7;
                    echo "finished callback: defer continued\n";
                });
            } else {
                Assert::true($release->push(true));
                Assert::same($finished, match ($request->streamId) {
                    9 => [1, 3, 7],
                    5 => [1, 3],
                    default => [1],
                });
                Assert::true($response->end($enabled ? 'K' : 'OK'));
            }
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
?>
--EXPECT--
default: request continued
request canceled
finished response: request continued
finished callback: defer continued
request canceled
finished response: request continued
finished callback: defer continued
