--TEST--
swoole_http2_server: reset a response stream and keep the connection open
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_flow_control.php';

use Swoole\Coroutine\Channel;

foreach ([SWOOLE_BASE, SWOOLE_PROCESS, 'coroutine'] as $mode) {
    $pm = new ProcessManager();
    $pm->parentFunc = function () use ($pm) {
        try {
            $peer = new Http2FlowPeer($pm->getFreePort());
            $frames = [];
            $read = function (int $id, int $type) use ($peer, &$frames) {
                do {
                    $frame = $peer->read();
                    if (in_array($frame['type'], [SWOOLE_HTTP2_TYPE_HEADERS, SWOOLE_HTTP2_TYPE_DATA, SWOOLE_HTTP2_TYPE_RST_STREAM], true)) {
                        $frames[$frame['streamId']][] = [$frame['type'], $frame['flags'], $frame['payload']];
                    }
                } while ($frame['streamId'] !== $id || $frame['type'] !== $type);
            };

            $peer->request(1, '/partial');
            $read(1, SWOOLE_HTTP2_TYPE_RST_STREAM);
            // The handler still holds the reset response while stream 3 is handled
            $peer->request(3, '/before-headers');
            $read(3, SWOOLE_HTTP2_TYPE_RST_STREAM);
            $peer->request(5, '/ok');
            $read(5, SWOOLE_HTTP2_TYPE_DATA);
            $peer->send(SWOOLE_HTTP2_TYPE_PING, 0, 0, 'barrier!');
            $read(0, SWOOLE_HTTP2_TYPE_PING);

            Assert::same(count($frames[1]), 3);
            Assert::same([$frames[1][0][0], $frames[1][0][1]], [SWOOLE_HTTP2_TYPE_HEADERS, 0x4]);
            Assert::same($frames[1][1], [SWOOLE_HTTP2_TYPE_DATA, 0, 'partial']);
            Assert::same($frames[1][2], [SWOOLE_HTTP2_TYPE_RST_STREAM, 0, pack('N', SWOOLE_HTTP2_ERROR_INTERNAL_ERROR)]);
            Assert::same($frames[3], [[SWOOLE_HTTP2_TYPE_RST_STREAM, 0, pack('N', SWOOLE_HTTP2_ERROR_CANCEL)]]);
            Assert::same($peer->bodies[5], 'OK');
            $peer->close();

            // After GOAWAY, resetting the last stream closes the connection
            $peer = new Http2FlowPeer($pm->getFreePort());
            $peer->request(1, '/goaway');
            $types = [];
            do {
                $frame = $peer->read();
                $types[] = $frame['type'];
            } while ($frame['type'] !== SWOOLE_HTTP2_TYPE_RST_STREAM);
            Assert::same(array_values(array_diff($types, [SWOOLE_HTTP2_TYPE_SETTINGS, SWOOLE_HTTP2_TYPE_WINDOW_UPDATE])), [
                SWOOLE_HTTP2_TYPE_GOAWAY,
                SWOOLE_HTTP2_TYPE_HEADERS,
                SWOOLE_HTTP2_TYPE_DATA,
                SWOOLE_HTTP2_TYPE_RST_STREAM,
            ]);
            $peer->closed();
            $peer->close();

            Assert::same(file_get_contents("http://127.0.0.1:{$pm->getFreePort()}/http1"), 'OK');
        } finally {
            $pm->kill();
        }
    };
    $pm->childFunc = function () use ($pm, $mode) {
        $channel = null;
        http2_flow_server($pm, $mode, function ($request, $response) use (&$channel) {
            $channel ??= new Channel(1);
            switch ($request->server['request_uri']) {
                case '/partial':
                    Assert::true($response->write('partial'));
                    Assert::true($response->reset());
                    Assert::false($response->isWritable());
                    Assert::false($response->write('more'));
                    Assert::false($response->end());
                    Assert::false($response->reset());
                    // With worker_max_concurrency 1, stream 3 runs only if the reset released this request's slot
                    Assert::true($channel->pop(5));
                    break;
                case '/before-headers':
                    Assert::true($response->reset(SWOOLE_HTTP2_ERROR_CANCEL));
                    $channel->push(true);
                    break;
                case '/goaway':
                    Assert::true($response->goaway());
                    Assert::true($response->write('partial'));
                    Assert::true($response->reset());
                    break;
                case '/http1':
                    Assert::false(@$response->reset());
                    Assert::contains(error_get_last()['message'], 'is not a HTTP2 connection');
                    $response->end('OK');
                    break;
                default:
                    $response->end('OK');
            }
        }, false, $mode === 'coroutine' ? [] : ['worker_max_concurrency' => 1]);
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
