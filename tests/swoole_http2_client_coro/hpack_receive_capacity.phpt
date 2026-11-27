--TEST--
swoole_http2_client_coro: synchronize HPACK receive capacity at SETTINGS acknowledgement
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_peer.php';

use Swoole\Coroutine\Http2\Client;
use Swoole\Coroutine\Socket;
use Swoole\Http2\Request;
use Swoole\Http2\Response;

function hpackInteger(int $value, int $bits, int $flags): string
{
    $maximum = (1 << $bits) - 1;
    if ($value < $maximum) {
        return chr($flags | $value);
    }
    $encoded = chr($flags | $maximum);
    $value -= $maximum;
    while ($value >= 128) {
        $encoded .= chr(($value & 127) | 128);
        $value >>= 7;
    }
    return $encoded . chr($value);
}

function receiveHeaders(Client $client, Socket $peer, int $id, string $block): Response
{
    http2_peer_send($peer, http2_test_frame(1, 5, $id, $block));
    $response = $client->recv(2);
    if (!$response instanceof Response) {
        throw new RuntimeException($client->errMsg);
    }
    Assert::same($response->streamId, $id);
    Assert::same($response->statusCode, 200);
    return $response;
}

Swoole\Coroutine\run(function () {
    $largeValue = str_repeat('Q', 5000);
    $largeBlock = hpackInteger(8192, 5, 0x20) . "\x88\x40\x05x-big"
        . hpackInteger(strlen($largeValue), 7, 0) . $largeValue;

    foreach ([false, true] as $ack) {
        Swoole\Coroutine::set(['http2_header_table_size' => 8192]);
        [$client, $peer, $settings] = http2_peer_open(1, $ack);
        Assert::same($client->stats('local_settings')['header_table_size'], 8192);
        Assert::same($client->stats('remote_settings')['header_table_size'], 4096);
        $advertised = [];
        for ($i = 0; $i < strlen($settings[3]); $i += 6) {
            $setting = unpack('nid/Nvalue', substr($settings[3], $i, 6));
            $advertised[$setting['id']] = $setting['value'];
        }
        Assert::same($advertised[1], 8192);
        Assert::same(receiveHeaders($client, $peer, 1, $largeBlock)->headers, ['x-big' => $largeValue]);
        Assert::same($client->send(new Request()), 3);
        if (!$ack) {
            // Applying the ACK must retain entries accepted under the larger capacity.
            http2_peer_send($peer, http2_test_frame(4, 1, 0));
        }
        Assert::same(receiveHeaders($client, $peer, 3, "\x88\xbe")->headers, ['x-big' => $largeValue]);
        $client->close();
        $peer->close();
    }

    foreach ([0, 128] as $capacity) {
        Swoole\Coroutine::set(['http2_header_table_size' => $capacity]);
        [$client, $peer] = http2_peer_open(1, false);
        Assert::same($client->stats('remote_settings')['header_table_size'], 4096);
        // The peer may still use the protocol's initial capacity before acknowledging a shrink.
        $beforeAck = hpackInteger(4096, 5, 0x20) . "\x88\x40\x08x-before\x03old";
        Assert::same(receiveHeaders($client, $peer, 1, $beforeAck)->headers, ['x-before' => 'old']);
        Assert::same($client->send(new Request()), 3);
        http2_peer_send($peer, http2_test_frame(4, 1, 0));
        Assert::same(receiveHeaders($client, $peer, 3, hpackInteger($capacity, 5, 0x20) . "\x88")->headers, []);
        Assert::same($client->send(new Request()), 5);
        http2_peer_send($peer, http2_test_frame(1, 5, 5, hpackInteger($capacity + 1, 5, 0x20) . "\x88"));
        Assert::false($client->recv(2));
        Assert::same($client->errCode, SWOOLE_HTTP2_ERROR_COMPRESSION_ERROR);
        Assert::false($client->connected);
        $peer->close();
    }

    // Reusing a Client starts a new decoder; dynamic entries cannot cross connections.
    Swoole\Coroutine::set(['http2_header_table_size' => 8192]);
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());
    $client = new Client('127.0.0.1', $listener->getsockname()['port']);
    for ($connection = 0; $connection < 2; ++$connection) {
        Assert::true($client->connect());
        $peer = $listener->accept(2);
        Assert::same($peer->recvAll(24, 2), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        Assert::same(http2_peer_read_frame($peer)[0], SWOOLE_HTTP2_TYPE_SETTINGS);
        Assert::same($client->send(new Request()), 1);
        http2_peer_send($peer, http2_test_frame(4, 0, 0) . http2_test_frame(4, 1, 0));
        if ($connection === 0) {
            Assert::same(receiveHeaders($client, $peer, 1, $largeBlock)->headers, ['x-big' => $largeValue]);
            $client->close();
        } else {
            http2_peer_send($peer, http2_test_frame(1, 5, 1, "\x88\xbe"));
            Assert::false($client->recv(2));
            Assert::same($client->errCode, SWOOLE_HTTP2_ERROR_COMPRESSION_ERROR);
            Assert::false($client->connected);
        }
        $peer->close();
    }
    $listener->close();
});
echo "DONE\n";
?>
--EXPECT--
DONE
