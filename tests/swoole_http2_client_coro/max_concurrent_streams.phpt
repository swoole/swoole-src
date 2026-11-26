--TEST--
swoole_http2_client_coro: honor the peer's concurrent stream limit
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http2\Client;
use Swoole\Coroutine\Socket;
use Swoole\Http2\Request;
use SwooleTest\Assert;

function readFrame(Socket $peer, int $type): array
{
    $header = $peer->recvAll(9, 2);
    Assert::same(strlen($header), 9);
    Assert::same(ord($header[3]), $type);
    $length = unpack('N', "\0" . substr($header, 0, 3))[1];
    $payload = $length ? $peer->recvAll($length, 2) : '';
    Assert::same(strlen($payload), $length);
    return [unpack('N', substr($header, 5, 4))[1], ord($header[4]), $payload];
}

function sendFrames(Socket $peer, string $frames): void
{
    Assert::same($peer->sendAll($frames, 2), strlen($frames));
}

function streamLimit(int $limit): string
{
    return http2_test_frame(4, 0, 0, pack('nN', 3, $limit));
}

function response(int $streamId): string
{
    return http2_test_frame(1, 5, $streamId, "\x88");
}

Assert::setThrowException(true);
Coroutine\run(function () {
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0) && $listener->listen());
    $client = new Client('127.0.0.1', $listener->getsockname()['port']);
    Assert::true($client->connect());
    $peer = $listener->accept(2);
    Assert::true($peer instanceof Socket);
    Assert::same($peer->recvAll(24, 2), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    readFrame($peer, 4);

    $warmup = $client->send(new Request());
    Assert::same(readFrame($peer, 1)[0], $warmup);
    sendFrames($peer, streamLimit(1) . response($warmup));
    Assert::same($client->recv(2)->streamId, $warmup);
    Assert::same(readFrame($peer, 4), [0, 1, '']);
    Assert::same($client->stats('remote_settings')['max_concurrent_streams'], 1);

    $request = new Request();
    $request->pipeline = true;
    $first = $client->send($request);
    Assert::same(readFrame($peer, 1)[0], $first);
    Assert::false($client->send(new Request()));
    Assert::same($client->errCode, SWOOLE_ERROR_HTTP2_TOO_MANY_STREAMS);
    Assert::same($client->stats('current_stream_id'), $first + 2);
    Assert::same($client->stats('active_stream_num'), 1);

    // A reduced limit leaves the half-closed stream usable until the upload ends.
    sendFrames($peer, streamLimit(0) . response($first));
    Assert::same($client->recv(2)->streamId, $first);
    Assert::same(readFrame($peer, 4), [0, 1, '']);
    Assert::same($client->stats('active_stream_num'), 1);
    Assert::true($client->write($first, 'tail', true));
    Assert::same(readFrame($peer, 0), [$first, 1, 'tail']);
    Assert::same($client->stats('active_stream_num'), 0);
    Assert::false($client->send(new Request()));
    Assert::same($client->errCode, SWOOLE_ERROR_HTTP2_TOO_MANY_STREAMS);

    sendFrames($peer, streamLimit(1));
    Assert::false($client->recv(0.05));
    Assert::same(readFrame($peer, 4), [0, 1, '']);

    // Header conversion can reenter send() and claim the last available stream slot.
    $header = new class ($client) {
        public int $streamId;

        public function __construct(private Client $client)
        {
        }

        public function __toString(): string
        {
            $this->streamId = $this->client->send(new Request());
            return 'unused';
        }
    };
    $request = new Request();
    $request->headers = ['x-test' => $header];
    Assert::false($client->send($request));
    Assert::same($client->errCode, SWOOLE_ERROR_HTTP2_TOO_MANY_STREAMS);
    Assert::same($header->streamId, $first + 2);
    Assert::same(readFrame($peer, 1)[0], $header->streamId);
    sendFrames($peer, response($header->streamId));
    Assert::same($client->recv(2)->streamId, $header->streamId);

    $last = $client->send(new Request());
    Assert::same($last, $header->streamId + 2);
    Assert::same(readFrame($peer, 1)[0], $last);
    sendFrames($peer, response($last));
    Assert::same($client->recv(2)->statusCode, 200);
    Assert::same($client->stats('active_stream_num'), 0);
    $client->close();
    $peer->close();
    $listener->close();
});
echo "DONE\n";
?>
--EXPECT--
DONE
