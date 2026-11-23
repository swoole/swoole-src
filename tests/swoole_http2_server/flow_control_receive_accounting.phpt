--TEST--
swoole_http2_server: count padded DATA payloads exactly and reject receive-window overruns
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
            $peer->send(0, 8, 1, "\x02ABCD\0\0");
            do {
                $frame = $peer->read();
            } while ($frame['type'] !== 8 || $frame['streamId'] !== 1);
            Assert::same(unpack('N', $frame['payload'])[1], 7);
            $peer->send(0, 9, 1, "\x02XYZ\0\0");
            $peer->bytes(1, 7);
            Assert::same($peer->bodies[1], 'ABCDXYZ');
            $peer->close();

            $peer = new Http2FlowPeer($pm->getFreePort());
            $peer->request(1, '/', false);
            $peer->send(0, 1, 1, '12345678'); // One byte beyond the advertised stream window.
            do {
                $frame = $peer->read();
            } while ($frame['type'] !== 3);
            Assert::same(unpack('N', $frame['payload'])[1], 3);
            $peer->request(3, '/');
            $peer->bytes(3, 5);
            Assert::same($peer->bodies[3], 'alive');
            $peer->close();
        } finally {
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        Swoole\Coroutine::set(['http2_init_window_size' => 7]);
        http2_flow_server($pm, $mode, function ($request, $response) {
            $response->end($request->rawContent() ?: 'alive');
        }, false, ['http2_init_window_size' => 7]);
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
