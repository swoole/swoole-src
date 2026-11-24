--TEST--
swoole_http2_server: zero-window waits release the writer and clean up on reset or throwing cancellation
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
            $peer = new Http2FlowPeer($pm->getFreePort(), 0);
            $peer->request(1, '/blocked');
            $peer->request(3, '/other');
            $peer->update(3, 3);
            $peer->bytes(3, 3);
            $peer->barrier();
            Assert::same($peer->bodies[3], 'XYZ');
            Assert::false(isset($peer->bodies[1]));
            $peer->send(3, 0, 1, pack('N', 8));
            $peer->request(5, '/cancel');
            $peer->barrier();
            while (!isset($peer->ended[5])) {
                $peer->read();
            }
            Assert::same($peer->bodies[5] ?? '', '');
            $peer->settings(2);
            $peer->request(7, '/alive');
            $peer->bytes(7, 2);
            Assert::same($peer->bodies[7], 'OK');
            $peer->close();
        } finally {
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        http2_flow_server($pm, $mode, function ($request, $response) {
            switch ($request->server['request_uri']) {
                case '/blocked':
                    Assert::false($response->end('NEVER'));
                    break;
                case '/other':
                    Assert::true($response->end('XYZ'));
                    break;
                case '/cancel':
                    $cid = Swoole\Coroutine::getCid();
                    Swoole\Event::defer(fn () => Swoole\Coroutine::cancel($cid, true));
                    try {
                        $response->write('NEVER');
                        Assert::true(false, 'expected cancellation while waiting for credit');
                    } catch (Swoole\Coroutine\CanceledException) {
                        Assert::true($response->end());
                    }
                    break;
                default:
                    $response->end('OK');
            }
        });
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
