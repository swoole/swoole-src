--TEST--
swoole_http2_server_coro: a blocked partial frame times out and closes without waiting to send GOAWAY
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_flow_control.php';

foreach ([false, true] as $tls) {
    $pm = new ProcessManager();
    $pm->setWaitTimeout(3);
    $pm->parentFunc = function () use ($pm, $tls) {
        try {
            $peer = new Http2FlowPeer($pm->getFreePort(), 0x7fffffff, $tls);
            $peer->update(0, 0x7fff0000);
            $peer->request(1, '/blocked');
            $started = microtime(true);
            // Do not read until the server's send has returned. This must not wait for socket capacity forever.
            Assert::true($pm->wait());
            Assert::lessThan(microtime(true) - $started, 2.0);
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
    $pm->childFunc = function () use ($pm, $tls) {
        http2_flow_server($pm, 'coroutine', function ($request, $response) use ($pm) {
            if ($request->server['request_uri'] === '/blocked') {
                Assert::false($response->end(str_repeat('A', 4 * 1024 * 1024)));
                $pm->wakeup();
            } else {
                $response->end('OK');
            }
        }, $tls, ['write_timeout' => 0.15, 'socket_buffer_size' => 4096]);
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
