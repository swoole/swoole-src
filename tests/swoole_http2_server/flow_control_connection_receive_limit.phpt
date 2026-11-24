--TEST--
swoole_http2_server: reject DATA beyond connection credit without unsigned wraparound
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_flow_control.php';

foreach ([SWOOLE_BASE, SWOOLE_PROCESS, 'coroutine'] as $mode) {
    $pm = new ProcessManager();
    $pm->parentFunc = function () use ($pm) {
        try {
            $peer = new Http2FlowPeer($pm->getFreePort());
            $peer->request(1, '/', false);
            // One frame exceeds the initial connection credit before any DATA-triggered update can be sent.
            $peer->send(0, 0, 1, str_repeat('A', 65536));
            do {
                $frame = $peer->read();
            } while ($frame['type'] !== 7);
            Assert::same(unpack('N', substr($frame['payload'], 4, 4))[1], 3);
            $peer->closed();
            $peer->close();
            $peer = new Http2FlowPeer($pm->getFreePort());
            $peer->request(1, '/');
            $peer->bytes(1, 2);
            Assert::same($peer->bodies[1], 'OK');
            $peer->close();
        } finally {
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        Swoole\Coroutine::set(['http2_max_frame_size' => 65536]);
        http2_flow_server($pm, $mode, fn ($request, $response) => $response->end('OK'), false,
            ['http2_max_frame_size' => 65536]);
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
