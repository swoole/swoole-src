--TEST--
swoole_http2_server: reject invalid flow-control increments and initial windows at the correct scope
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
            foreach ([[0, 1], [0x7fffffff, 3]] as [$increment, $error]) {
                $peer = new Http2FlowPeer($pm->getFreePort());
                // Leave the request incomplete so it still has a stream-level window.
                $peer->request(1, '/', false);
                $peer->update(1, $increment);
                do {
                    $frame = $peer->read();
                } while ($frame['type'] !== 3);
                Assert::same($frame['streamId'], 1);
                Assert::same(unpack('N', $frame['payload'])[1], $error);
                $peer->request(3, '/');
                $peer->bytes(3, 2);
                Assert::same($peer->bodies[3], 'OK');
                $peer->close();
            }
            foreach ([[0, 1], [0x7fffffff, 3]] as [$increment, $error]) {
                $peer = new Http2FlowPeer($pm->getFreePort());
                $peer->update(0, $increment);
                do {
                    $frame = $peer->read();
                } while ($frame['type'] !== 7);
                Assert::same(unpack('N', substr($frame['payload'], 4, 4))[1], $error);
                $peer->closed();
                $peer->close();
            }
            $peer = new Http2FlowPeer($pm->getFreePort());
            $peer->send(8, 0, 0, "bad");
            do {
                $frame = $peer->read();
            } while ($frame['type'] !== 7);
            Assert::same(unpack('N', substr($frame['payload'], 4, 4))[1], 6);
            $peer->closed();
            $peer->close();
            $peer = new Http2FlowPeer($pm->getFreePort(), 0x80000000);
            do {
                $frame = $peer->read();
            } while ($frame['type'] !== 7);
            Assert::same(unpack('N', substr($frame['payload'], 4, 4))[1], 3);
            $peer->closed();
            $peer->close();
        } finally {
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        http2_flow_server($pm, $mode, fn ($request, $response) => $response->end('OK'));
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
