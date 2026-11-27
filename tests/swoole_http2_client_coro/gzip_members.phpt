--TEST--
swoole_http2_client_coro: decode all gzip members and reject incomplete representations
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('zlib');
skip_if_constant_not_defined('SWOOLE_HAVE_ZLIB');
?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http2\Client;
use Swoole\Coroutine\Socket;
use Swoole\Http2\Request;
use Swoole\Http2\Response;
use SwooleTest\Assert;

Assert::setThrowException(true);

function readGzipFrame(Socket $peer): array
{
    $header = $peer->recvAll(9, 2);
    Assert::same(strlen($header), 9);
    $length = unpack('N', "\0" . substr($header, 0, 3))[1];
    $payload = $length ? $peer->recvAll($length, 2) : '';
    Assert::same(strlen($payload), $length);
    return [ord($header[3]), unpack('N', substr($header, 5, 4))[1], $payload];
}

function gzipPeer(Client $client, Socket $listener, ?int $window = null): Socket
{
    Assert::true($client->connect());
    $peer = $listener->accept(2);
    Assert::isInstanceOf($peer, Socket::class);
    Assert::same($peer->recvAll(24, 2), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    Assert::same(readGzipFrame($peer)[0], SWOOLE_HTTP2_TYPE_SETTINGS);
    gzipFrames($peer, http2_test_frame(4, 0, 0, $window === null ? '' : pack('nN', 4, $window)));
    return $peer;
}

function gzipRequest(Client $client, Socket $peer, string $method = 'GET'): int
{
    $request = new Request();
    $request->method = $method;
    $id = $client->send($request);
    Assert::greaterThan($id, 0);
    Assert::same(array_slice(readGzipFrame($peer), 0, 2), [SWOOLE_HTTP2_TYPE_HEADERS, $id]);
    return $id;
}

function gzipFrames(Socket $peer, string $frames): void
{
    Assert::same($peer->sendAll($frames), strlen($frames));
}

Coroutine\run(function () {
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());
    $client = new Client('127.0.0.1', $listener->getsockname()['port']);
    $one = gzencode('one');
    $two = gzencode('two');
    $crc = $two;
    $crc[strlen($crc) - 8] = chr(ord($crc[strlen($crc) - 8]) ^ 0xff);
    $large = str_repeat('large decoded member ', 4096);
    $cases = [
        'same-frame' => [[$one . $two], 'onetwo', true],
        'member-boundary' => [[$one, $two], 'onetwo', true],
        'empty-final-frame' => [[$one, $two, ''], 'onetwo', true],
        'byte-boundaries' => [str_split($one . $two), 'onetwo', true],
        'empty-members' => [[gzencode('') . $one . gzencode('') . $two], 'onetwo', true],
        'empty-body' => [[gzencode('')], '', true],
        'large-members' => [[gzencode($large) . gzencode($large)], $large . $large, true],
        'truncated-trailer' => [[$one . substr($two, 0, -1)], '', false],
        'split-truncated-trailer' => [[$one, substr($two, 0, -1)], '', false],
        'truncated-header' => [[$one, substr($two, 0, 1)], '', false],
        'no-member' => [[], '', false],
        'bad-crc' => [[$one . $crc], '', false],
        'trailing-garbage' => [[$one, 'garbage'], '', false],
    ];
    try {
        foreach ($cases as [$chunks, $expected, $valid]) {
            foreach ([false, true] as $pipeline) {
                foreach ([false, true] as $trailers) {
                    $peer = gzipPeer($client, $listener);
                    try {
                        $id = gzipRequest($client, $peer);
                        // Literal Content-Encoding, indexed name 26, followed by "gzip".
                        $headers = "\x88\x0f\x0b\x04gzip";
                        $frames = http2_test_frame(1, $chunks || $trailers ? 4 : 5, $id, $headers);
                        foreach ($chunks as $index => $chunk) {
                            $end = !$trailers && $index === count($chunks) - 1;
                            $frames .= http2_test_frame(0, $end ? 1 : 0, $id, $chunk);
                        }
                        if ($trailers) {
                            $frames .= http2_test_frame(1, 5, $id);
                        }
                        gzipFrames($peer, $frames);
                        $decoded = '';
                        do {
                            $response = $pipeline ? $client->read(2) : $client->recv(2);
                            if ($response === false) {
                                break;
                            }
                            Assert::isInstanceOf($response, Response::class);
                            Assert::same($response->streamId, $id);
                            $decoded .= $response->data;
                        } while ($response->pipeline);
                        if ($valid) {
                            Assert::isInstanceOf($response, Response::class);
                            Assert::same($decoded, $expected);
                            Assert::true($client->connected);
                        } else {
                            Assert::false($response);
                            Assert::same($client->errCode, SWOOLE_ERROR_HTTP_INVALID_PROTOCOL);
                            Assert::false($client->connected);
                        }
                        Assert::same($client->stats('active_stream_num'), 0);
                    } finally {
                        $client->close();
                        $peer->close();
                    }
                }
            }
        }

        // Encoding metadata does not require a compressed body for HEAD, 204 or 304.
        foreach ([['HEAD', "\x88"], ['GET', "\x89"], ['GET', "\x8b"]] as [$method, $status]) {
            $peer = gzipPeer($client, $listener);
            $id = gzipRequest($client, $peer, $method);
            gzipFrames($peer, http2_test_frame(1, 5, $id, $status . "\x0f\x0b\x04gzip"));
            $response = $client->recv(2);
            Assert::isInstanceOf($response, Response::class);
            Assert::same($response->data, null);
            Assert::true($client->connected);
            $client->close();
            $peer->close();
        }

        // Each interleaved stream maintains its own member completion state.
        $peer = gzipPeer($client, $listener);
        $first = gzipRequest($client, $peer);
        $second = gzipRequest($client, $peer);
        gzipFrames($peer, http2_test_frame(1, 4, $first, "\x88\x0f\x0b\x04gzip")
            . http2_test_frame(1, 4, $second, "\x88\x0f\x0b\x04gzip")
            . http2_test_frame(0, 0, $first, $one)
            . http2_test_frame(0, 0, $second, substr($two, 0, 5))
            . http2_test_frame(0, 1, $first, $two)
            . http2_test_frame(0, 1, $second, substr($two, 5) . $one));
        Assert::same($client->recv(2)->data, 'onetwo');
        Assert::same($client->recv(2)->data, 'twoone');
        $client->close();
        $peer->close();

        // The upload-side buffering budget applies to all decoded members, not just each member separately.
        $client->set(['http2_max_buffered_response_bytes' => 4000]);
        $peer = gzipPeer($client, $listener, 1);
        $warmup = gzipRequest($client, $peer);
        gzipFrames($peer, http2_test_frame(1, 5, $warmup, "\x88"));
        Assert::isInstanceOf($client->recv(2), Response::class);
        Assert::same(readGzipFrame($peer)[0], SWOOLE_HTTP2_TYPE_SETTINGS);
        $finished = new Swoole\Coroutine\Channel(1);
        Coroutine::create(function () use ($peer, $finished) {
            [$type, $id] = readGzipFrame($peer);
            Assert::same($type, SWOOLE_HTTP2_TYPE_HEADERS);
            Assert::same(readGzipFrame($peer)[2], 'a');
            $member = gzencode(str_repeat('x', 3000));
            gzipFrames($peer, http2_test_frame(1, 4, $id, "\x88\x0f\x0b\x04gzip")
                . http2_test_frame(0, 0, $id, $member . $member));
            Assert::same($peer->recv(1, 2), '');
            $peer->close();
            $finished->push(true);
        });
        $request = new Request();
        $request->method = 'POST';
        $request->data = 'ab';
        Assert::false($client->send($request));
        Assert::same($client->errCode, SOCKET_ENOBUFS);
        Assert::false($client->connected);
        Assert::true($finished->pop(2));
    } finally {
        $client->close();
        $listener->close();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
