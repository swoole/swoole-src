--TEST--
swoole_http2_client_coro: uploads respect both send windows and preserve received responses
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Http2\Client;
use Swoole\Coroutine\Socket;
use Swoole\Http2\Request;
use Swoole\Http2\Response;

function check(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

function readFrame(Socket $socket, int $type): array
{
    $header = $socket->recvAll(9, 2);
    check(is_string($header) && strlen($header) === 9, "missing frame of type $type");
    check(ord($header[3]) === $type, "expected frame type $type, got " . ord($header[3]));
    $length = unpack('N', "\0" . substr($header, 0, 3))[1];
    $data = $length === 0 ? '' : $socket->recvAll($length, 2);
    check(is_string($data) && strlen($data) === $length, 'missing frame payload');
    return [unpack('N', substr($header, 5, 4))[1], ord($header[4]), $data];
}

function sendFrames(Socket $socket, string $frames): void
{
    check($socket->sendAll($frames, 2) === strlen($frames), 'failed to send peer frames');
}

function settings(int $window): string
{
    return http2_test_frame(4, 0, 0, pack('nN', 4, $window));
}

function grant(int $stream, int $credit): string
{
    return http2_test_frame(8, 0, $stream, pack('N', $credit));
}

function withCreditLimitedPeer(Socket $listener, callable $handle, array $options = [], int $streams = 128): void
{
    Coroutine::create(static function () use ($listener, $handle, $streams) {
        $peer = $listener->accept(2);
        check($peer instanceof Socket, 'accept failed');
        check($peer->recvAll(24, 2) === "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 'missing client preface');
        readFrame($peer, 4);
        [$warmup] = readFrame($peer, 1);
        sendFrames($peer, http2_test_frame(4, 0, 0, pack('nNnN', 4, 1, 3, $streams))
            . http2_test_frame(1, 5, $warmup, "\x88"));
        check(readFrame($peer, 4) === [0, 1, ''], 'missing SETTINGS ACK');
        $handle($peer);
        $peer->close();
    });

    $client = new Client('127.0.0.1', $listener->getsockname()['port']);
    $client->set($options + ['write_timeout' => 2]);
    check($client->connect(), 'connect failed');
    $warmup = $client->send(new Request());
    check($warmup !== false && $client->recv(2)->streamId === $warmup, 'warmup failed');
    $handle($client);
}

function uploadRequest(string $data = 'abc'): Request
{
    $request = new Request();
    $request->method = 'POST';
    $request->data = $data;
    return $request;
}

Coroutine\run(static function () {
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    check($listener->bind('127.0.0.1', 0) && $listener->listen(), 'listen failed');

    Coroutine::create(static function () use ($listener) {
        $peer = $listener->accept(2);
        check($peer instanceof Socket, 'accept failed');
        check($peer->recvAll(24, 2) === "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 'missing client preface');
        readFrame($peer, 4);
        [$warmup] = readFrame($peer, 1);
        sendFrames($peer, settings(65537) . http2_test_frame(1, 5, $warmup, "\x88"));
        check(readFrame($peer, 4) === [0, 1, ''], 'missing initial SETTINGS ACK');

        [$other] = readFrame($peer, 1);
        [$upload] = readFrame($peer, 1);
        $received = 0;
        while ($received < 65535) {
            [$stream, $flags, $data] = readFrame($peer, 0);
            check($stream === $upload && $flags === 0 && $data !== '', 'unexpected upload DATA');
            $received += strlen($data);
            check($received <= 65535, 'DATA exceeded the connection window');
        }

        // The stream has two bytes left. Reducing the initial window by three gives it a debt of one.
        sendFrames($peer, http2_test_frame(1, 5, $other, "\x88")
            . settings(65534) . grant(0, 5) . grant($upload, 1) . http2_test_frame(6, 0, 0, '12345678'));
        check(readFrame($peer, 4) === [0, 1, ''], 'missing SETTINGS decrease ACK');
        check(readFrame($peer, 6) === [0, 1, '12345678'], 'DATA was sent while the stream window was zero');
        sendFrames($peer, grant($upload, 2));
        check(readFrame($peer, 0) === [$upload, 0, 'bc'], 'DATA exceeded the renewed stream window');

        sendFrames($peer, settings(65544));
        check(readFrame($peer, 4) === [0, 1, ''], 'missing SETTINGS increase ACK');
        check(readFrame($peer, 0) === [$upload, 0, 'def'], 'SETTINGS changed the connection window');
        sendFrames($peer, grant(0, 1));
        check(readFrame($peer, 0) === [$upload, 1, 'g'], 'wrong final DATA');
        sendFrames($peer, http2_test_frame(1, 5, $upload, "\x88"));
        check($peer->recv(1, 2) === '', 'client did not close');
        $peer->close();
    });

    $client = new Client('127.0.0.1', $listener->getsockname()['port']);
    $client->set(['write_timeout' => 2]);
    check($client->connect(), 'connect failed');
    $warmup = $client->send(new Request());
    check($warmup !== false && $client->recv(2)->streamId === $warmup, 'warmup request failed');

    $other = $client->send(new Request());
    check($other !== false, 'second request failed');
    $request = new Request();
    $request->method = 'POST';
    $request->data = str_repeat('a', 65535) . 'bcdefg';
    $upload = $client->send($request);
    check($upload !== false, 'large request failed');

    foreach ([$other, $upload] as $stream) {
        $response = $client->recv(2);
        check($response instanceof Response && $response->streamId === $stream, 'response was lost during upload');
        check($response->statusCode === 200, 'unexpected response status');
    }

    $client->close();

    Coroutine::create(static function () use ($listener) {
        $peer = $listener->accept(2);
        check($peer instanceof Socket, 'pipeline accept failed');
        check($peer->recvAll(24, 2) === "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 'missing client preface');
        readFrame($peer, 4);
        [$warmup] = readFrame($peer, 1);
        sendFrames($peer, settings(3) . http2_test_frame(1, 5, $warmup, "\x88"));
        check(readFrame($peer, 4) === [0, 1, ''], 'missing SETTINGS ACK');
        [$pipeline] = readFrame($peer, 1);
        check(readFrame($peer, 0) === [$pipeline, 0, 'abc'], 'write exceeded the stream window');
        sendFrames($peer, grant($pipeline, 2));
        check(readFrame($peer, 0) === [$pipeline, 0, 'de'], 'write did not use renewed credit');
        check(readFrame($peer, 0) === [$pipeline, 1, ''], 'empty END_STREAM must work with no credit');
        sendFrames($peer, http2_test_frame(1, 5, $pipeline, "\x88"));
        check($peer->recv(1, 2) === '', 'pipeline client did not close');
        $peer->close();
    });

    check($client->connect(), 'reconnect failed');
    $warmup = $client->send(new Request());
    check($warmup !== false && $client->recv(2)->streamId === $warmup, 'pipeline warmup failed');
    $request = new Request();
    $request->method = 'POST';
    $request->pipeline = true;
    $pipeline = $client->send($request);
    check($pipeline !== false, 'failed to start pipeline');
    $response = new Channel(1);
    Coroutine::create(static fn () => $response->push($client->recv(2)));
    check($client->write($pipeline, 'abcde'), 'pipeline DATA write failed');
    check($client->write($pipeline, '', true), 'pipeline END_STREAM write failed');
    $result = $response->pop(2);
    check($result instanceof Response && $result->streamId === $pipeline, 'concurrent receiver lost pipeline response');
    $client->close();

    $invalidWindows = [
        [http2_test_frame(4, 0, 0, pack('n', 4) . "\x80\0\0\0"), SWOOLE_HTTP2_ERROR_FLOW_CONTROL_ERROR],
        [grant(0, 0x7fffffff), SWOOLE_HTTP2_ERROR_FLOW_CONTROL_ERROR],
        [grant(0, 0), SWOOLE_HTTP2_ERROR_PROTOCOL_ERROR],
    ];
    foreach ($invalidWindows as [$frame, $error]) {
        Coroutine::create(static function () use ($listener, $frame, $error) {
            $peer = $listener->accept(2);
            check($peer instanceof Socket, 'invalid window accept failed');
            check($peer->recvAll(24, 2) === "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 'missing client preface');
            readFrame($peer, 4);
            sendFrames($peer, $frame);
            [$stream, , $payload] = readFrame($peer, 7);
            check($stream === 0 && unpack('N', substr($payload, 4, 4))[1] === $error, 'incorrect GOAWAY error');
            $peer->close();
        });
        check($client->connect(), 'invalid window connect failed');
        check($client->recv(2) === false && !$client->connected, 'invalid window was accepted');
        check($client->errCode === $error, 'incorrect connection error');
    }

    withCreditLimitedPeer($listener, static function (Socket|Client $endpoint) {
        if ($endpoint instanceof Socket) {
            [$first] = readFrame($endpoint, 1);
            [$second] = readFrame($endpoint, 1);
            [$upload] = readFrame($endpoint, 1);
            check(readFrame($endpoint, 0) === [$upload, 0, 'a'], 'upload did not exhaust its window');
            sendFrames($endpoint, http2_test_frame(1, 5, $first, "\x88")
                . http2_test_frame(1, 5, $second, "\x88")
                . http2_test_frame(7, 0, 0, pack('NN', $second, 0) . 'draining'));
            check($endpoint->recv(1, 2) === '', 'GOAWAY did not close the client');
            return;
        }
        $first = $endpoint->send(new Request());
        $second = $endpoint->send(new Request());
        check($endpoint->send(uploadRequest()) === false && !$endpoint->connected, 'upload survived GOAWAY');
        check($endpoint->read(2)->streamId === $first, 'read lost the first response after GOAWAY');
        check($endpoint->recv(2)->streamId === $second, 'recv lost the second response after GOAWAY');
        check($endpoint->recv(2) === false && $endpoint->errMsg === 'draining', 'GOAWAY diagnostic was lost');
    });

    foreach ([false, true] as $upload) {
        withCreditLimitedPeer($listener, static function (Socket|Client $endpoint) use ($upload) {
            $error = SWOOLE_HTTP2_ERROR_REFUSED_STREAM;
            if ($endpoint instanceof Socket) {
                [$other] = readFrame($endpoint, 1);
                [$reset] = readFrame($endpoint, 1);
                if ($upload) {
                    check(readFrame($endpoint, 0) === [$reset, 0, 'a'], 'upload did not exhaust its window');
                }
                $rst = http2_test_frame(3, 0, $reset, pack('N', $error));
                // The duplicate reset must not become another response or affect the other stream.
                sendFrames($endpoint, $rst . $rst . http2_test_frame(1, 5, $other, "\x88"));
                check($endpoint->recv(1, 2) === '', 'client did not close');
                return;
            }

            $other = $endpoint->send(new Request());
            check($other !== false, 'failed to start the other stream');
            $request = new Request();
            $request->pipeline = $upload;
            $reset = $endpoint->send($request);
            check($reset !== false, 'failed to start the stream to reset');
            if ($upload) {
                check($endpoint->write($reset, 'abc', true) === false, 'write survived RST_STREAM');
                check($endpoint->errCode === SWOOLE_ERROR_HTTP2_STREAM_NOT_FOUND, 'write error changed');
            }
            $response = $upload ? $endpoint->recv(2) : $endpoint->read(2);
            check($response instanceof Response && $response->streamId === $reset, 'reset result was lost');
            check($response->errCode === $error && $response->statusCode === SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET,
                'reset result lost the peer error');
            check(!$endpoint->isStreamExist($reset), 'reset stream was retained');
            $response = $endpoint->recv(2);
            check($response instanceof Response && $response->streamId === $other && $response->statusCode === 200,
                'reset affected the other stream');
            $endpoint->close();
        });
    }

    foreach ([[false, false], [false, true], [true, true]] as [$pipeline, $reset]) {
        withCreditLimitedPeer($listener, static function (Socket|Client $endpoint) use ($pipeline, $reset) {
            if ($endpoint instanceof Socket) {
                [$upload] = readFrame($endpoint, 1);
                check(readFrame($endpoint, 0) === [$upload, 0, 'a'], 'upload did not exhaust its window');
                $response = http2_test_frame(1, 5, $upload, "\x08\x03" . '413');
                sendFrames($endpoint, $response . ($reset ? http2_test_frame(3, 0, $upload, pack('N', 0)) : grant($upload, 2)));
                if (!$reset) {
                    check(readFrame($endpoint, 0) === [$upload, 1, 'bc'], 'response END_STREAM stopped the request');
                }
                [$next] = readFrame($endpoint, 1);
                sendFrames($endpoint, http2_test_frame(1, 5, $next, "\x88"));
                check($endpoint->recv(1, 2) === '', 'client did not close');
                return;
            }
            if ($pipeline) {
                $request = uploadRequest('');
                $request->pipeline = true;
                $upload = $endpoint->send($request);
                check($upload !== false && !$endpoint->write($upload, 'abc', true), 'write survived RST_STREAM');
                check(str_contains($endpoint->errMsg, 'after sending the response'), 'write lost the reset reason');
            } else {
                $upload = $endpoint->send(uploadRequest());
                check($upload !== false, 'send lost the stream ID for a complete response');
            }
            $response = $endpoint->recv(2);
            check($response instanceof Response && $response->streamId === $upload && $response->statusCode === 413,
                'early response was lost');
            check(!$endpoint->isStreamExist($upload), 'closed stream was retained');
            $next = $endpoint->send(new Request());
            check($next !== false && $endpoint->recv(2)->streamId === $next, 'connection was unusable after early response');
            $endpoint->close();
        });
    }

    withCreditLimitedPeer($listener, static function (Socket|Client $endpoint) {
        if ($endpoint instanceof Socket) {
            [$complete] = readFrame($endpoint, 1);
            [$partial] = readFrame($endpoint, 1);
            [$upload] = readFrame($endpoint, 1);
            check(readFrame($endpoint, 0) === [$upload, 0, 'a'], 'upload did not exhaust its window');
            sendFrames($endpoint, http2_test_frame(1, 5, $complete, "\x88")
                . http2_test_frame(1, 4, $partial, "\x88")
                . http2_test_frame(0, 0, $partial, str_repeat('b', 50)));
            check($endpoint->recv(1, 2) === '', 'buffer limit did not close the client');
            return;
        }
        $complete = $endpoint->send(new Request());
        check($complete !== false && $endpoint->send(new Request()) !== false, 'could not start downloads');
        check($endpoint->send(uploadRequest()) === false && !$endpoint->connected, 'buffer limit was ignored');
        check(str_contains($endpoint->errMsg, 'buffering limit'), 'wrong error for full response buffer');
        check($endpoint->recv(2)->streamId === $complete, 'buffer limit discarded a complete response');
        check($endpoint->recv(2) === false, 'incomplete response was delivered');
    }, ['http2_max_buffered_response_bytes' => 128]);

    if (defined('SWOOLE_HAVE_ZLIB') && function_exists('gzencode')) {
        $body = str_repeat('g', 12288);
        foreach ([256, 16384] as $limit) {
            withCreditLimitedPeer($listener, static function (Socket|Client $endpoint) use ($body, $limit) {
                if ($endpoint instanceof Socket) {
                    [$download] = readFrame($endpoint, 1);
                    [$upload] = readFrame($endpoint, 1);
                    check(readFrame($endpoint, 0) === [$upload, 0, 'a'], 'upload did not exhaust its window');
                    sendFrames($endpoint, http2_test_frame(1, 4, $download, "\x88\x5a\x04gzip")
                        . http2_test_frame(0, 1, $download, gzencode($body)));
                    if ($limit > strlen($body)) {
                        sendFrames($endpoint, grant($upload, 2));
                        check(readFrame($endpoint, 0) === [$upload, 1, 'bc'], 'upload did not use new credit');
                        sendFrames($endpoint, http2_test_frame(1, 5, $upload, "\x88"));
                    }
                    check($endpoint->recv(1, 2) === '', 'client did not close');
                    return;
                }
                $download = $endpoint->send(new Request());
                $upload = $endpoint->send(uploadRequest());
                if ($limit > strlen($body)) {
                    $response = $endpoint->recv(2);
                    check($response instanceof Response && $response->streamId === $download && $response->data === $body,
                        'gzip response was damaged while buffering');
                    check($upload !== false && $endpoint->recv(2)->streamId === $upload, 'upload failed after gzip response');
                    $endpoint->close();
                } else {
                    check($upload === false && !$endpoint->connected, 'decoded body was allowed to exceed the limit');
                    check(str_contains($endpoint->errMsg, 'buffering limit'), 'wrong error for oversized gzip response');
                }
            }, ['http2_max_buffered_response_bytes' => $limit]);
        }
    }

    withCreditLimitedPeer($listener, static function (Socket|Client $endpoint) {
        if ($endpoint instanceof Socket) {
            $responses = '';
            for ($i = 0; $i < 129; ++$i) {
                [$stream] = readFrame($endpoint, 1);
                $responses .= http2_test_frame(1, 5, $stream, "\x88");
            }
            [$upload] = readFrame($endpoint, 1);
            check(readFrame($endpoint, 0) === [$upload, 0, 'a'], 'upload did not exhaust its window');
            sendFrames($endpoint, $responses);
            check($endpoint->recv(1, 2) === '', 'response queue limit did not close the client');
            return;
        }
        $streams = [];
        for ($i = 0; $i < 129; ++$i) {
            $stream = $endpoint->send(new Request());
            check($stream !== false, 'could not start download');
            $streams[] = $stream;
        }
        check($endpoint->send(uploadRequest()) === false && !$endpoint->connected, 'response queue limit was ignored');
        foreach (array_slice($streams, 0, 128) as $stream) {
            check($endpoint->recv(2)->streamId === $stream, 'wrong queued response');
        }
        check($endpoint->recv(2) === false && str_contains($endpoint->errMsg, 'buffering limit'), 'queue limit error was lost');
    }, [], 256);

    $listener->close();
});
echo "DONE\n";
?>
--EXPECT--
DONE
