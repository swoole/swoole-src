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
    $listener->close();
});
echo "DONE\n";
?>
--EXPECT--
DONE
