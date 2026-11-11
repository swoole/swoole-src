--TEST--
swoole_http2_server: a write waiting for the connection leaves whole frames when it fails or its stream is reset
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;

// Parses every frame from the start of the connection until $streamId ends, and counts DATA bytes per stream.
function read_until_end($client, int $streamId): array
{
    $bytes = [];
    while (true) {
        $frame = http2_test_read_frame($client);
        if ($frame === false) {
            throw new RuntimeException('failed to read HTTP/2 frame');
        }
        if ($frame['type'] === 4 && ($frame['flags'] & 1) === 0) {
            fwrite($client, http2_test_frame(4, 1, 0));
        }
        if ($frame['type'] === 0) {
            $bytes[$frame['streamId']] = ($bytes[$frame['streamId']] ?? 0) + strlen($frame['payload']);
            if ($frame['streamId'] === $streamId && ($frame['flags'] & 1)) {
                return $bytes;
            }
        }
    }
}

$cases = [
    // The reset stream's writer is cancelled while it waits.
    'cancel' => [
        function (ProcessManager $pm, $client) {
            Assert::true($pm->wait());
            fwrite($client, http2_test_frame(3, 0, 1, pack('N', 8)));
            Assert::true($pm->wait());
            fwrite($client, http2_test_request_headers(3, '/'));
            Assert::same(read_until_end($client, 3)[3], 2);
        },
        function (Swoole\Http\Server $server, ProcessManager $pm) {
            $writer = null;
            $server->on('Request', function ($request, $response) use ($pm, &$writer) {
                if ($request->streamId === 3) {
                    $response->end('OK');
                    return;
                }
                $writer = [Coroutine::getCid(), $response];
                $pm->wakeup();
                try {
                    $response->write(str_repeat('A', 16 * 1024 * 1024));
                } catch (Coroutine\CanceledException) {
                    echo "writer cancelled\n";
                }
                $pm->wakeup();
            });
            $server->on('StreamReset', function () use (&$writer) {
                [$cid, $response] = $writer;
                Assert::false($response->isWritable());
                Assert::false($response->write('x'));
                Assert::true(Coroutine::cancel($cid, true));
            });
        },
    ],
    // The write times out without any reset.
    'send_timeout' => [
        function (ProcessManager $pm, $client) {
            Assert::true($pm->wait());
            Assert::true($pm->wait());
            fwrite($client, http2_test_request_headers(3, '/'));
            Assert::same(read_until_end($client, 3)[3], 2);
        },
        function (Swoole\Http\Server $server, ProcessManager $pm) {
            $server->set(['send_timeout' => 0.5]);
            $server->on('Request', function ($request, $response) use ($pm) {
                if ($request->streamId === 3) {
                    $response->end('OK');
                    return;
                }
                $pm->wakeup();
                var_dump($response->write(str_repeat('A', 16 * 1024 * 1024)));
                $pm->wakeup();
            });
        },
    ],
    // Stream 3's last frame waits behind stream 1 when stream 3 is reset, and isn't sent.
    'final frame' => [
        function (ProcessManager $pm, $client) {
            fwrite($client, http2_test_request_headers(3, '/'));
            Assert::true($pm->wait());
            fwrite($client, http2_test_frame(3, 0, 3, pack('N', 8)));
            Assert::true($pm->wait());
            Assert::same(read_until_end($client, 1)[3], 1);
            fwrite($client, http2_test_request_headers(5, '/'));
            Assert::same(read_until_end($client, 5)[5], 2);
        },
        function (Swoole\Http\Server $server, ProcessManager $pm) {
            $go1 = new Channel(1);
            $go3 = new Channel(1);
            $server->on('Request', function ($request, $response) use ($pm, $go1, $go3) {
                if ($request->streamId === 1) {
                    $go1->pop();
                    // Runs once this write is waiting for the connection.
                    Swoole\Event::defer(fn () => $go3->push(true));
                    $response->write(str_repeat('A', 16 * 1024 * 1024));
                    $response->end();
                } elseif ($request->streamId === 3) {
                    Assert::true($response->write('x'));
                    $go1->push(true);
                    $go3->pop();
                    $pm->wakeup();
                    var_dump($response->write(str_repeat('B', 16384)));
                } else {
                    $response->end('OK');
                }
            });
            $server->on('StreamReset', function () use ($pm) {
                $pm->wakeup();
            });
        },
    ],
];

foreach ($cases as $name => [$parent, $child]) {
    echo "{$name}\n";
    $pm = new ProcessManager;
    $pm->setWaitTimeout(5);
    $pm->parentFunc = function () use ($pm, $parent) {
        // The client doesn't read until it parses the frames, so writes fill the buffers and wait in send_yield.
        $client = http2_test_open_request($pm->getFreePort(), '/', 0x7fffffff);
        try {
            $parent($pm, $client);
        } finally {
            fclose($client);
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $child) {
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
        $server->set([
            'log_file' => '/dev/null',
            'open_http2_protocol' => true,
            'http_compression' => false,
            'send_yield' => true,
            'buffer_output_size' => 1024 * 1024,
        ]);
        $server->on('WorkerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $child($server, $pm);
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
?>
--EXPECT--
cancel
writer cancelled
send_timeout
bool(false)
final frame
bool(false)
