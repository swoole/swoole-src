--TEST--
swoole_http2_server: finish existing streams and process WINDOW_UPDATE while draining after GOAWAY
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_flow_control.php';

foreach ([SWOOLE_BASE, SWOOLE_PROCESS, 'coroutine'] as $mode) {
    foreach ([false, true] as $tls) {
        $pm = new ProcessManager();
        $pm->parentFunc = function () use ($pm, $tls) {
            try {
                $peer = new Http2FlowPeer($pm->getFreePort(), 0, $tls);
                $peer->request(1, '/upload', false);
                $peer->request(3, '/drain');
                do {
                    $frame = $peer->read();
                } while ($frame['type'] !== 7);
                Assert::same(unpack('Nlast/Nerror', substr($frame['payload'], 0, 8)), ['last' => 3, 'error' => 0]);

                // Requests sent before the client learns about GOAWAY can still arrive. Ignore this request,
                // but decode its fragmented header block: the existing upload's trailer references its entry.
                $headers = substr(http2_test_request_headers(5, '/ignored'), 9) . "\x40\x08x-goaway\x07indexed";
                $peer->send(1, 0, 5, substr($headers, 0, 5));
                $peer->send(9, 4, 5, substr($headers, 5));
                $peer->update(5, 1);
                for ($i = 0; $i < 3; ++$i) {
                    $peer->send(0, $i === 2 ? 1 : 0, 5, str_repeat('I', 11000));
                }
                do {
                    $frame = $peer->read();
                } while ($frame['type'] !== 8 || $frame['streamId'] !== 0);
                Assert::same(unpack('N', $frame['payload'])[1], 33000);
                $peer->barrier();
                Assert::same($peer->total, 0);

                // SETTINGS and stream credit still apply to existing streams, without dispatching new ones.
                $peer->settings(0);
                $peer->update(1, 2);
                $peer->send(0, 0, 1, 'UP');
                $peer->send(1, 5, 1, "\xbe");
                $peer->bytes(1, 2);
                Assert::same($peer->bodies[1], 'UP');
                $peer->update(3, 70000);
                $peer->bytes(3, 65533);
                $peer->barrier();
                Assert::same($peer->total, 65535);
                Assert::false(isset($peer->ended[3]));
                $peer->update(0, 70000 - 65533);
                $peer->bytes(3, 70000);
                Assert::same($peer->bodies[3], str_repeat('D', 70000));
                Assert::true(isset($peer->ended[1], $peer->ended[3]));
                $peer->closed();
                $peer->close();
            } finally {
                $pm->kill();
            }
        };
        $pm->childFunc = function () use ($pm, $mode, $tls) {
            http2_flow_server($pm, $mode, function ($request, $response) {
                if ($request->server['request_uri'] === '/drain') {
                    Assert::true($response->goaway());
                    Assert::true($response->end(str_repeat('D', 70000)));
                } else {
                    Assert::same($request->server['request_uri'], '/upload');
                    Assert::same($request->trailer['x-goaway'], 'indexed');
                    Assert::true($response->end($request->rawContent()));
                }
            }, $tls);
        };
        $pm->childFirst();
        $pm->run();
    }
}
echo "DONE\n";
?>
--EXPECT--
DONE
