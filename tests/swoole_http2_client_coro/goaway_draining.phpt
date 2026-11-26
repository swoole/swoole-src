--TEST--
swoole_http2_client_coro: drain in-flight streams after a normal GOAWAY
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http2\Client;
use Swoole\Coroutine\Socket;
use Swoole\Http2\Request;
use Swoole\Http2\Response;

Assert::setThrowException(true);

function readFrame(Socket $peer, int $type): array
{
    $header = $peer->recvAll(9, 2);
    Assert::same(strlen($header), 9);
    Assert::same(ord($header[3]), $type);
    $length = unpack('N', "\0" . substr($header, 0, 3))[1];
    $data = $length ? $peer->recvAll($length, 2) : '';
    Assert::same(strlen($data), $length);
    return [unpack('N', substr($header, 5, 4))[1], ord($header[4]), $data];
}

function connectPeer(Client $client, Socket $listener): Socket
{
    Assert::true($client->connect());
    $peer = $listener->accept(2);
    Assert::true($peer instanceof Socket);
    Assert::same($peer->recvAll(24, 2), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    readFrame($peer, 4);
    return $peer;
}

function sendFrames(Socket $peer, string $frames): void
{
    Assert::same($peer->sendAll($frames), strlen($frames));
}

function goaway(int $last, string $message): string
{
    return http2_test_frame(7, 0, 0, pack('NN', $last, SWOOLE_HTTP2_ERROR_NO_ERROR) . $message);
}

function checkRefused(Client $client, int $stream): void
{
    $response = $client->recv(2);
    Assert::true($response instanceof Response);
    Assert::same($response->streamId, $stream);
    Assert::same($response->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET);
    Assert::same($response->errCode, SWOOLE_HTTP2_ERROR_REFUSED_STREAM);
    Assert::false($client->isStreamExist($stream));
}

Coroutine\run(function () {
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0) && $listener->listen());
    $client = new Client('127.0.0.1', $listener->getsockname()['port']);

    $peer = connectPeer($client, $listener);
    $request = new Request();
    $request->pipeline = true;
    $first = $client->send($request);
    $second = $client->send(new Request());
    $third = $client->send(new Request());
    foreach ([$first, $second, $third] as $id) {
        Assert::same(readFrame($peer, 1)[0], $id);
    }

    sendFrames($peer, goaway($second, 'begin drain'));
    checkRefused($client, $third);
    Assert::true($client->connected);
    Assert::same($client->serverLastStreamId, $second);
    Assert::false($client->send(new Request()));
    Assert::same($client->stats('active_stream_num'), 2);

    sendFrames($peer, goaway($first, 'finish drain')
        . http2_test_frame(1, 4, $first, "\x88")
        . http2_test_frame(0, 1, $first, 'response'));
    checkRefused($client, $second);
    $response = $client->read(2);
    Assert::true($response instanceof Response);
    Assert::same($response->streamId, $first);
    Assert::same($response->statusCode, 200);
    Assert::same($response->data, 'response');
    Assert::true($client->connected);
    Assert::true($client->write($first, 'upload tail', true));
    Assert::same(readFrame($peer, 0), [$first, 1, 'upload tail']);
    Assert::same($peer->recv(1, 2), '');
    Assert::false($client->connected);
    Assert::false($client->recv(2));
    Assert::same($client->errCode, SWOOLE_HTTP2_ERROR_NO_ERROR);
    Assert::same($client->errMsg, 'finish drain');
    Assert::same($client->serverLastStreamId, $first);
    $peer->close();

    // A reconnect accepts new requests. A complete final response is returned before closing.
    $peer = connectPeer($client, $listener);
    $id = $client->send(new Request());
    Assert::same(readFrame($peer, 1)[0], $id);
    sendFrames($peer, goaway($id | 0x80000000, 'done') . http2_test_frame(1, 5, $id, "\x88"));
    $response = $client->recv(2);
    Assert::true($response instanceof Response);
    Assert::same($response->streamId, $id);
    Assert::same($response->statusCode, 200);
    Assert::same($client->serverLastStreamId, $id);
    Assert::false($client->connected);
    Assert::same($peer->recv(1, 2), '');
    $peer->close();

    // The drain deadline applies both to an indefinite recv() and to an idle client.
    $client->set(['read_timeout' => 0.15]);
    foreach ([true, false] as $waiting) {
        $peer = connectPeer($client, $listener);
        $allowed = $client->send(new Request());
        $refused = $client->send(new Request());
        Assert::same(readFrame($peer, 1)[0], $allowed);
        Assert::same(readFrame($peer, 1)[0], $refused);
        sendFrames($peer, goaway($allowed, 'waiting'));
        checkRefused($client, $refused);
        if (!$waiting) {
            Coroutine::sleep(0.3);
        }
        Assert::false($client->recv(-1));
        Assert::false($client->connected);
        Assert::same($client->errCode, SOCKET_ETIMEDOUT);
        Assert::same($client->serverLastStreamId, $allowed);
        Assert::same($peer->recv(1, 2), '');
        $peer->close();
    }
    $listener->close();
});
echo "DONE\n";
?>
--EXPECT--
DONE
