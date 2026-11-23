--TEST--
swoole_http2_server: return connection credit reserved by a DATA frame canceled before enqueue
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_flow_control.php';

const CREDIT = 1024 * 1024;
foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $pm = new ProcessManager();
    $pm->setWaitTimeout(3);
    $pm->parentFunc = function () use ($pm) {
        try {
            // Constrain the client too: macOS can otherwise buffer the entire connection allowance,
            // making this a window wait rather than the intended canceled output-buffer wait.
            $peer = new Http2FlowPeer($pm->getFreePort(), CREDIT, false, 65536);
            $peer->update(0, CREDIT - 65535);
            $peer->request(1, '/blocked');
            Assert::true($pm->wait());
            $peer->send(3, 0, 1, pack('N', 8));
            Assert::true($pm->wait());
            // The handler queues this marker after the reset; draining it consumes every accepted DATA frame.
            do {
                $frame = $peer->read();
            } while ($frame['type'] !== 6 || $frame['payload'] !== 'refunded');
            $remaining = CREDIT - $peer->total;
            Assert::greaterThan($remaining, 0);
            $peer->request(3, '/' . $remaining);
            $peer->bytes(3, $remaining);
            Assert::true(isset($peer->ended[3]));
            Assert::same($peer->total, CREDIT);
            Assert::same(strspn($peer->bodies[3], 'B'), $remaining);
            $peer->close();
        } finally {
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        http2_flow_server($pm, $mode, function ($request, $response, $server) use ($pm) {
            if ($request->server['request_uri'] === '/blocked') {
                Assert::true($response->write('A'));
                // Fill transport queues without spending HTTP/2 credit. The filler only yields when
                // Server::send() waits for output space; stop it there before reserving the next DATA frame.
                $filler = Swoole\Coroutine::create(function () use ($server, $request) {
                    $extension = http2_test_frame(15, 0, 0, str_repeat('P', 16384));
                    for ($i = 0; $i < 4096 && $server->send($request->fd, $extension); ++$i) {
                    }
                });
                Assert::true(Swoole\Coroutine::cancel($filler));
                Swoole\Event::defer(fn () => $pm->wakeup());
                try {
                    $response->write(str_repeat('A', 2 * CREDIT));
                    Assert::true(false, 'expected cancellation during output-buffer wait');
                } catch (Swoole\Coroutine\CanceledException) {
                    $pm->wakeup();
                    Assert::true($server->send($request->fd, http2_test_frame(6, 1, 0, 'refunded')));
                }
            } else {
                Assert::true($response->end(str_repeat('B', (int) substr($request->server['request_uri'], 1))));
            }
        }, false, [
            'http2_cancel_on_stream_reset' => true,
            'http_compression' => false,
            'send_yield' => true,
            'send_timeout' => 2,
            'socket_buffer_size' => 65536,
            'buffer_output_size' => 65536,
            'kernel_socket_send_buffer_size' => 4096,
        ]);
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
