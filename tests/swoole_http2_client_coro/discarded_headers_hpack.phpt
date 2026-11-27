--TEST--
swoole_http2_client_coro: discarded header blocks preserve HPACK and CONTINUATION state
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_peer.php';

Swoole\Coroutine\run(function () {
    [$client, $peer] = http2_peer_open(2);
    // A zero WINDOW_UPDATE causes the client to reset stream 1. These headers were already in flight.
    // The discarded, padded/priority-bearing block inserts x-old: b, split inside its literal name.
    http2_peer_send($peer, http2_test_frame(8, 0, 1, pack('N', 0))
        . http2_test_frame(1, 0x28, 1, "\x02" . pack('NC', 0, 16) . "\x88\x40\x05x-\0\0")
        . http2_test_frame(9, 0, 1, 'ol')
        . http2_test_frame(9, 4, 1, "d\x01b")
        . http2_test_frame(1, 5, 3, "\x88\xbe"));
    $response = $client->recv(2);
    Assert::isInstanceOf($response, Swoole\Http2\Response::class);
    Assert::same($response->streamId, 3);
    Assert::same($response->statusCode, 200);
    Assert::same($response->headers, ['x-old' => 'b']);
    $client->close();
    $peer->close();

    foreach ([false, true] as $ack) {
        Swoole\Coroutine::set(['http2_enable_push' => (int) $ack]);
        [$client, $peer] = http2_peer_open(2, $ack);
        // Even before a disabled-push SETTINGS has been acknowledged, an in-flight promise must be decoded.
        $push = "\x82\x86\x84\x01\x09localhost\x40\x06x-push\x01p";
        http2_peer_send($peer, http2_test_frame(5, 0, 1, pack('N', 2) . substr($push, 0, 9))
            . http2_test_frame(9, 4, 1, substr($push, 9))
            // An already queued response to the rejected push inserts another connection-wide entry.
            . http2_test_frame(1, 5, 2, "\x88\x40\x06x-late\x01b")
            . http2_test_frame(1, 5, 1, "\x88\xbf")
            . http2_test_frame(1, 5, 3, "\x88\xbe\xbf"));
        $response = $client->recv(2);
        Assert::same($response->streamId, 1);
        Assert::same($response->headers, ['x-push' => 'p']);
        $response = $client->recv(2);
        Assert::same($response->streamId, 3);
        Assert::same($response->headers, ['x-late' => 'b', 'x-push' => 'p']);
        do {
            $frame = http2_peer_read_frame($peer);
        } while ($frame[0] !== SWOOLE_HTTP2_TYPE_RST_STREAM);
        Assert::same($frame, [3, 0, 2, pack('N', SWOOLE_HTTP2_ERROR_CANCEL)]);
        $client->close();
        $peer->close();
    }

    Swoole\Coroutine::set(['http2_enable_push' => 0]);
    foreach (['compression', 'sequence', 'disabled-push'] as $case) {
        [$client, $peer] = http2_peer_open(2);
        if ($case === 'disabled-push') {
            $frames = http2_test_frame(5, 4, 1, pack('N', 2) . "\x82\x86\x84");
            $error = SWOOLE_HTTP2_ERROR_PROTOCOL_ERROR;
        } else {
            $frames = http2_test_frame(8, 0, 1, pack('N', 0));
            if ($case === 'compression') {
                // Indexed field 0 is invalid, including when the owning stream has been discarded.
                $frames .= http2_test_frame(1, 4, 1, "\x80");
                $error = SWOOLE_HTTP2_ERROR_COMPRESSION_ERROR;
            } else {
                $frames .= http2_test_frame(1, 0, 1, "\x88") . http2_test_frame(1, 5, 3, "\x88");
                $error = SWOOLE_HTTP2_ERROR_PROTOCOL_ERROR;
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
