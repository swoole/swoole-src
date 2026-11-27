<?php
/** Loopback HTTP/2 peer for coroutine-client protocol regressions. */

require_once __DIR__ . '/http2_raw_client.php';

function http2_peer_read_frame(Swoole\Coroutine\Socket $peer): array
{
    $header = $peer->recvAll(9, 2);
    if (!is_string($header) || strlen($header) !== 9) {
        throw new RuntimeException('Failed to receive an HTTP/2 frame header');
    }
    $length = unpack('N', "\0" . substr($header, 0, 3))[1];
    $payload = $length ? $peer->recvAll($length, 2) : '';
    if (!is_string($payload) || strlen($payload) !== $length) {
        throw new RuntimeException('Failed to receive an HTTP/2 frame payload');
    }
    return [ord($header[3]), ord($header[4]), unpack('N', substr($header, 5, 4))[1] & 0x7fffffff, $payload];
}

function http2_peer_send(Swoole\Coroutine\Socket $peer, string $frames): void
{
    Assert::same($peer->sendAll($frames), strlen($frames));
}

function http2_peer_open(int $requests = 1, bool $ack = true): array
{
    $listener = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());
    $client = new Swoole\Coroutine\Http2\Client('127.0.0.1', $listener->getsockname()['port']);
    Assert::true($client->connect());
    $peer = $listener->accept(2);
    $listener->close();
    Assert::same($peer->recvAll(24, 2), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    $settings = http2_peer_read_frame($peer);
    Assert::same($settings[0], SWOOLE_HTTP2_TYPE_SETTINGS);
    for ($i = 0; $i < $requests; ++$i) {
        Assert::same($client->send(new Swoole\Http2\Request()), $i * 2 + 1);
    }
    $received = 0;
    while ($received < $requests) {
        $frame = http2_peer_read_frame($peer);
        $received += $frame[0] === SWOOLE_HTTP2_TYPE_HEADERS;
    }
    http2_peer_send($peer, http2_test_frame(4, 0, 0) . ($ack ? http2_test_frame(4, 1, 0) : ''));
    return [$client, $peer, $settings];
}
