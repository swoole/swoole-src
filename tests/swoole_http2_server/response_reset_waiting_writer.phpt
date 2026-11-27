--TEST--
swoole_http2_server: reset a response stream while its writer waits
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('sockets');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_flow_control.php';

use Swoole\Event;

foreach ([SWOOLE_BASE, SWOOLE_PROCESS, 'coroutine'] as $mode) {
    $pm = new ProcessManager();
    $pm->parentFunc = function () use ($pm, $mode) {
        try {
            // A write waiting for window credit returns when another coroutine resets its stream
            $peer = new Http2FlowPeer($pm->getFreePort(), 0);
            $peer->request(1, '/window');
            do {
                $frame = $peer->read();
                Assert::notSame($frame['type'], SWOOLE_HTTP2_TYPE_DATA);
            } while ($frame['type'] !== SWOOLE_HTTP2_TYPE_RST_STREAM);
            Assert::same($frame['payload'], pack('N', SWOOLE_HTTP2_ERROR_INTERNAL_ERROR));
            Assert::true($pm->wait());
            $peer->barrier();
            $peer->close();

            if ($mode !== SWOOLE_BASE) {
                return;
            }

            // A reset can't overtake HEADERS waiting for output buffer space
            $peer = new Http2FlowPeer($pm->getFreePort(), 65535, false, 4096);
            $peer->request(1, '/pending-headers');
            Assert::true($pm->wait());
            while (!isset($peer->ended[1])) {
                Assert::notSame($peer->read()['type'], SWOOLE_HTTP2_TYPE_RST_STREAM);
            }
            Assert::same($peer->bodies[1], 'OK');
            $peer->close();

            // A reset waiting for output buffer space keeps its deadline after the writer returns, and is sent once
            // the client reads
            $peer = new Http2FlowPeer($pm->getFreePort(), 0, false, 4096);
            $peer->request(1, '/full-buffer');
            Assert::true($pm->wait());
            do {
                $frame = $peer->read();
                Assert::notSame($frame['type'], SWOOLE_HTTP2_TYPE_GOAWAY);
            } while ($frame['type'] !== SWOOLE_HTTP2_TYPE_RST_STREAM);
            Assert::same($frame['payload'], pack('N', SWOOLE_HTTP2_ERROR_INTERNAL_ERROR));
            $peer->barrier();
            $peer->close();
        } finally {
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        http2_flow_server($pm, $mode, function ($request, $response, $server = null) use ($pm) {
            switch ($request->server['request_uri']) {
                case '/window':
                    Event::defer(fn () => go(fn () => Assert::true($response->reset())));
                    Assert::false($response->write('NEVER'));
                    $pm->wakeup();
                    break;
                case '/pending-headers':
                    http2_test_fill_send_buffer($server, $request->fd);
                    Event::defer(function () use ($pm, $response) {
                        Assert::false($response->reset());
                        Assert::true($response->isWritable());
                        $pm->wakeup();
                    });
                    Assert::true($response->write('OK'));
                    Assert::true($response->end());
                    break;
                case '/full-buffer':
                    Event::defer(function () use ($server, $request, $response) {
                        http2_test_fill_send_buffer($server, $request->fd);
                        // Queued ahead of the reset, these sends fill the output buffer again when senders resume,
                        // so the reset waits a second time
                        $frames = str_repeat(http2_test_frame(15, 0, 0, str_repeat('S', 16384)), 8);
                        go(function () use ($server, $request, $frames) {
                            Assert::true($server->send($request->fd, $frames));
                            Assert::true($server->send($request->fd, $frames));
                        });
                        go(fn () => Assert::true($response->reset()));
                    });
                    Assert::false($response->write('NEVER'));
                    $pm->wakeup();
                    break;
            }
        }, false, $mode === 'coroutine' ? [] : [
            'send_yield' => true,
            'socket_buffer_size' => 64 * 1024,
            'kernel_socket_send_buffer_size' => 4096,
        ]);
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
