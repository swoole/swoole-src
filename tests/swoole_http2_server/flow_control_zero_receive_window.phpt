--TEST--
swoole_http2_server: empty DATA at a zero receive window must not produce a zero WINDOW_UPDATE
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
            $peer->send(0, 1, 1);
            $peer->bytes(1, 2);
            $peer->barrier();
            Assert::same($peer->bodies[1], 'OK');
            Assert::true(isset($peer->ended[1]));
            $peer->close();
        } finally {
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        Swoole\Coroutine::set(['http2_init_window_size' => 0]);
        http2_flow_server($pm, $mode, fn ($request, $response) => $response->end('OK'), false,
            ['http2_init_window_size' => 0]);
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
