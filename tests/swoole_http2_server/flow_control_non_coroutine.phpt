--TEST--
swoole_http2_server: internal writers drain end and sendfile without turning synchronous callbacks into coroutines
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_flow_control.php';

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $tls) {
        $file = tempnam(sys_get_temp_dir(), 'swoole-http2-sync-');
        file_put_contents($file, 'prefix' . str_repeat('F', 70000) . 'suffix');
        $pm = new ProcessManager();
        $pm->parentFunc = function () use ($pm, $tls, $file) {
            try {
                $peer = new Http2FlowPeer($pm->getFreePort(), 0, $tls);
                $peer->request(1, '/end');
                $peer->request(3, '/file');
                $peer->barrier();
                Assert::same($peer->total, 0);
                Assert::false(file_exists($file));
                $peer->update(1, 70000);
                $peer->update(3, 70000);
                while ($peer->total < 65535) {
                    $peer->read();
                }
                $peer->barrier();
                Assert::same($peer->total, 65535);
                $peer->update(0, 140000 - 65535);
                while (!isset($peer->ended[1], $peer->ended[3])) {
                    $peer->read();
                }
                Assert::same($peer->bodies[1], str_repeat('E', 70000));
                Assert::same($peer->bodies[3], str_repeat('F', 70000));
                $peer->close();

                $peer = new Http2FlowPeer($pm->getFreePort(), 0, $tls);
                $peer->request(1, '/blocked');
                do {
                    $frame = $peer->read();
                } while ($frame['type'] !== 7);
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
                if (file_exists($file)) {
                    unlink($file);
                }
            }
        };
        $pm->childFunc = function () use ($pm, $mode, $tls, $file) {
            http2_flow_server($pm, $mode, function ($request, $response) use ($file) {
                Assert::same(Swoole\Coroutine::getCid(), -1);
                switch ($request->server['request_uri']) {
                    case '/end':
                        $data = str_repeat('E', 70000);
                        Assert::true($response->end($data));
                        $data[0] = 'Z'; // The pending writer must retain its own string reference.
                        break;
                    case '/file':
                        Assert::true($response->sendfile($file, 6, 70000, true));
                        break;
                    case '/blocked':
                        Assert::true($response->end(str_repeat('B', 70000)));
                        break;
                    default:
                        Assert::true($response->end('OK'));
                }
                Assert::false($response->isWritable());
                Assert::same(Swoole\Coroutine::getCid(), -1);
            }, $tls, ['enable_coroutine' => false, 'send_timeout' => 0.5]);
        };
        $pm->childFirst();
        $pm->run();
    }
}
echo "DONE\n";
?>
--EXPECT--
DONE
