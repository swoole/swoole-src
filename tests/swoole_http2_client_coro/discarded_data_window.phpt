--TEST--
swoole_http2_client_coro: discarded DATA replenishes connection credit without reopening closed streams
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_peer.php';

Swoole\Coroutine\run(function () {
    foreach ([65535, 131072] as $window) {
        Swoole\Coroutine::set(['http2_init_window_size' => $window, 'http2_enable_push' => 1]);
        [$client, $peer] = http2_peer_open($window === 65535 ? 2 : 1);
        if ($window === 65535) {
            $closed = 1;
            $active = 3;
            $frames = http2_test_frame(8, 0, $closed, pack('N', 0));
            $expected = 32768;
        } else {
            $closed = 2;
            $active = 1;
            $frames = http2_test_frame(5, 4, 1, pack('N', 2) . "\x82\x86\x84\x01\x09localhost");
            $expected = 65536;
        }
        // Padding is flow-controlled even when the application discards every byte of this stream.
        for ($i = 0; $i < 4; ++$i) {
            $length = $window === 65535 && $i === 3 ? 16383 : 16384;
            $payload = "\x07" . str_repeat('X', $length - 8) . str_repeat("\0", 7);
            $frames .= http2_test_frame(0, 8, $closed, $payload);
        }
        $frames .= http2_test_frame(1, 4, $active, "\x88");
        http2_peer_send($peer, $frames);
        $continued = false;
        go(function () use ($peer, $closed, $active, $expected, &$continued) {
            do {
                $frame = http2_peer_read_frame($peer);
                Assert::false($frame[0] === 8 && $frame[2] === $closed);
            } while ($frame[0] !== 8 || $frame[2] !== 0);
            Assert::same(unpack('N', $frame[3])[1], $expected);
            http2_peer_send($peer, http2_test_frame(0, 1, $active, 'active response'));
            $continued = true;
        });
        $response = $client->recv(3);
        Assert::isInstanceOf($response, Swoole\Http2\Response::class);
        Assert::same($response->streamId, $active);
        Assert::same($response->data, 'active response');
        Assert::true($continued);
        $client->close();
        $peer->close();
    }

    Swoole\Coroutine::set(['http2_init_window_size' => 65535, 'http2_enable_push' => 0,
        'http2_max_frame_size' => 131072]);
    foreach (['idle', 'zero', 'padding', 'window'] as $case) {
        [$client, $peer] = http2_peer_open();
        $frames = '';
        $error = SWOOLE_HTTP2_ERROR_PROTOCOL_ERROR;
        if ($case === 'idle' || $case === 'zero') {
            $frames = http2_test_frame(0, 0, $case === 'idle' ? 3 : 0, 'X');
        } else {
            $frames = http2_test_frame(8, 0, 1, pack('N', 0));
            if ($case === 'padding') {
                $frames .= http2_test_frame(0, 8, 1, "\x01");
            } else {
                $frames .= http2_test_frame(0, 0, 1, str_repeat('X', 65536));
                $error = SWOOLE_HTTP2_ERROR_FLOW_CONTROL_ERROR;
            }
        }
        http2_peer_send($peer, $frames);
        Assert::false($client->recv(2));
        Assert::same($client->errCode, $error);
        Assert::false($client->connected);
        $peer->close();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
