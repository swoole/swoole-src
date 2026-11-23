--TEST--
swoole_http2_server: an async response keeps its deadline across a yielding trailer conversion
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_flow_control.php';

class DelayedFlowTrailer
{
    public function __toString(): string
    {
        Swoole\Coroutine::sleep(0.15);
        return 'late';
    }
}

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $tls) {
        $pm = new ProcessManager();
        $pm->parentFunc = function () use ($pm, $tls) {
            try {
                $peer = new Http2FlowPeer($pm->getFreePort(), 65535, $tls);
                $peer->request(1, '/delayed');
                do {
                    $frame = $peer->read();
                } while ($frame['type'] !== 7);
                Assert::same($peer->bodies[1], 'A');
                Assert::false(isset($peer->ended[1]));
                Assert::same(unpack('N', substr($frame['payload'], 4, 4))[1], 0);
                $peer->closed();
                $peer->close();
                $peer = new Http2FlowPeer($pm->getFreePort(), 65535, $tls);
                $peer->request(1, '/alive');
                $peer->bytes(1, 2);
                Assert::same($peer->bodies[1], 'OK');
                $peer->close();
            } finally {
                $pm->kill();
            }
        };
        $pm->childFunc = function () use ($pm, $mode, $tls) {
            http2_flow_server($pm, $mode, function ($request, $response) {
                if ($request->server['request_uri'] === '/delayed') {
                    $response->trailer = ['x-delayed' => new DelayedFlowTrailer()];
                    Assert::false($response->end('A'));
                } else {
                    Assert::true($response->end('OK'));
                }
            }, $tls, ['send_timeout' => 0.05]);
        };
        $pm->childFirst();
        $pm->run();
    }
}
echo "DONE\n";
?>
--EXPECT--
DONE
