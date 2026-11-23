--TEST--
swoole_http2_server: account stream and connection credit across updates and SETTINGS changes
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_flow_control.php';

foreach ([SWOOLE_BASE, SWOOLE_PROCESS, 'coroutine'] as $mode) {
    foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $tls) {
        $pm = new ProcessManager();
        $pm->parentFunc = function () use ($pm, $tls) {
            try {
                $peer = new Http2FlowPeer($pm->getFreePort(), 0, $tls);
                $peer->request(1, '/6');
                $peer->request(3, '/0');
                $peer->barrier();
                Assert::same($peer->bodies, []);
                Assert::true(isset($peer->ended[3]));
                $peer->update(1, 2);
                $peer->bytes(1, 2);
                $peer->barrier();
                Assert::same($peer->bodies[1], 'AA');
                $peer->update(1, 4);
                $peer->bytes(1, 6);
                Assert::true(isset($peer->ended[1]));

                // Shrinking the initial window creates debt, not an unsigned allowance.
                $peer->settings(5);
                $peer->request(5, '/10');
                $peer->bytes(5, 5);
                $peer->settings(0);
                $peer->update(5, 5);
                $peer->barrier();
                Assert::same(strlen($peer->bodies[5]), 5);
                $peer->update(5, 2);
                $peer->bytes(5, 7);
                $peer->settings(3);
                $peer->bytes(5, 10);
                Assert::true(isset($peer->ended[5]));

                // SETTINGS affects stream windows only. A stream update cannot replace connection credit.
                $peer->settings(200000);
                $available = 65535 - $peer->total;
                $peer->request(7, '/70000');
                $peer->bytes(7, $available);
                $peer->update(7, 10000);
                $peer->barrier();
                Assert::same(strlen($peer->bodies[7]), $available);
                $peer->update(0, 0x80000000 | (70000 - $available)); // Reserved bit is ignored.
                $peer->bytes(7, 70000);
                Assert::same($peer->bodies[7], str_repeat('A', 70000));
                Assert::true(isset($peer->ended[7]));
                $peer->close();
            } finally {
                $pm->kill();
            }
        };
        $pm->childFunc = function () use ($pm, $mode, $tls) {
            http2_flow_server($pm, $mode, function ($request, $response) {
                $response->end(str_repeat('A', (int) substr($request->server['request_uri'], 1)));
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
