--TEST--
swoole_http2_client_coro: receiving can resume after a fragmented frame times out
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Http2\Client;
use Swoole\Coroutine\Socket;

function checkFrame(bool $condition): void
{
    if (!$condition) {
        throw new RuntimeException('Fragmented HTTP/2 frame assertion failed');
    }
}

function frame(int $type, int $flags, int $stream, string $payload = ''): string
{
    return substr(pack('N', strlen($payload)), 1) . pack('CCN', $type, $flags, $stream) . $payload;
}

Coroutine\run(function () {
    foreach ([2, 9, 12] as $split) {
        $listener = new Socket(AF_INET, SOCK_STREAM, 0);
        checkFrame($listener->bind('127.0.0.1', 0) && $listener->listen());
        $ready = new Channel(1);
        $resume = new Channel(1);
        $body = 'fragmented response';
        Coroutine::create(function () use ($listener, $ready, $resume, $body, $split) {
            $peer = $listener->accept(2);
            checkFrame($peer instanceof Socket);
            $peer->setOption(SOL_SOCKET, SO_RCVTIMEO, ['sec' => 2, 'usec' => 0]);
            checkFrame($peer->recvAll(24) === "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            // Consume the client's SETTINGS and request HEADERS before replying.
            do {
                $header = $peer->recvAll(9);
                checkFrame(is_string($header) && strlen($header) === 9);
                $length = unpack('N', "\0" . substr($header, 0, 3))[1];
                if ($length > 0) {
                    $payload = $peer->recvAll($length);
                    checkFrame(is_string($payload) && strlen($payload) === $length);
                }
            } while (ord($header[3]) !== 1);
            // HPACK index 8 is :status = 200; the DATA frame ends stream 1.
            $prefix = frame(4, 0, 0) . frame(1, 4, 1, "\x88");
            $data = frame(0, 1, 1, $body);
            $prefix .= substr($data, 0, $split);
            checkFrame($peer->sendAll($prefix) === strlen($prefix));
            $ready->push(true);
            checkFrame($resume->pop(2) === true);
            $remaining = substr($data, $split);
            checkFrame($peer->sendAll($remaining) === strlen($remaining));
            // Drain SETTINGS acknowledgements until the client closes. Closing a
            // Winsock connection with unread data can reset it before DATA is read.
            while (($received = $peer->recv()) !== '') {
                checkFrame($received !== false);
            }
            $peer->close();
        });
        $client = new Client('127.0.0.1', $listener->getsockname()['port']);
        $client->set(['timeout' => 2]);
        checkFrame($client->connect());
        checkFrame($client->send(new Swoole\Http2\Request) === 1);
        checkFrame($ready->pop(2) === true);
        for ($i = 0; $i < 2; $i++) {
            checkFrame($client->recv(0.01) === false);
            checkFrame($client->errCode === SOCKET_ETIMEDOUT);
            checkFrame($client->connected);
        }
        $resume->push(true);
        $response = $client->recv(2);
        checkFrame($response instanceof Swoole\Http2\Response);
        checkFrame($response->statusCode === 200 && $response->streamId === 1 && $response->data === $body);
        $client->close();
        $listener->close();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
