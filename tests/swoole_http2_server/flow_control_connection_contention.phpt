--TEST--
swoole_http2_server: concurrent streams never spend the same connection credit twice
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
            $peer = new Http2FlowPeer($pm->getFreePort(), 200000);
            $peer->request(1, '/1');
            $peer->request(3, '/3');
            while ($peer->total < 65535) {
                $peer->read();
            }
            $peer->barrier();
            Assert::same($peer->total, 65535);
            $granted = 65535;
            while ($granted < 200000) {
                $grant = min(17003, 200000 - $granted);
                $peer->update(0, $grant);
                $granted += $grant;
                while ($peer->total < $granted) {
                    $peer->read();
                }
                $peer->barrier();
                Assert::same($peer->total, $granted);
            }
            Assert::same($peer->bodies[1], str_repeat('1', 100000));
            Assert::same($peer->bodies[3], str_repeat('3', 100000));
            Assert::true(isset($peer->ended[1], $peer->ended[3]));
            $peer->close();
        } finally {
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        http2_flow_server($pm, $mode, fn ($request, $response) =>
            $response->end(str_repeat(substr($request->server['request_uri'], 1), 100000)));
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
