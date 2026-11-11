--TEST--
swoole_http2_client_coro: stream reset by the server while its data is being sent
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Http2\Client;
use Swoole\Coroutine\Socket;
use Swoole\Http2\Request;

const HTTP2_FLAG_ACK     = 0x1;
const HTTP2_ERROR_CANCEL = 0x8;

function http2_frame(int $type, int $flags, int $streamId, string $payload = ''): string
{
    return substr(pack('N', strlen($payload)), 1)
        . chr($type)
        . chr($flags)
        . pack('N', $streamId & 0x7FFFFFFF)
        . $payload;
}

foreach (['send', 'write'] as $method) {
    Coroutine\run(function () use ($method) {
        $listener = new Socket(AF_INET, SOCK_STREAM, 0);
        Assert::true($listener->bind('127.0.0.1'));
        Assert::true($listener->listen());
        $drain = new Channel(1);
        // Resets stream 1 on its first DATA frame, then stops reading until drained.
        go(function () use ($listener, $drain) {
            $connection = $listener->accept();
            $connection->sendAll(http2_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 0, 0));
            Assert::same($connection->recvAll(24, -1), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            while (strlen($header = $connection->recvAll(9, -1)) === 9) {
                $length = unpack('N', "\0" . substr($header, 0, 3))[1];
                if ($length > 0) {
                    $connection->recvAll($length, -1);
                }
                $type = ord($header[3]);
                if ($type === SWOOLE_HTTP2_TYPE_SETTINGS && !(ord($header[4]) & HTTP2_FLAG_ACK)) {
                    $connection->sendAll(http2_frame(SWOOLE_HTTP2_TYPE_SETTINGS, HTTP2_FLAG_ACK, 0));
                } elseif ($type === SWOOLE_HTTP2_TYPE_DATA) {
                    $connection->sendAll(http2_frame(SWOOLE_HTTP2_TYPE_RST_STREAM, 0, 1, pack('N', HTTP2_ERROR_CANCEL)));
                    $drain->pop();
                    while (($data = $connection->recv(65536, -1)) !== '' && $data !== false) {
                    }
                    break;
                }
            }
            $connection->close();
        });

        $client = new Client('127.0.0.1', $listener->getsockname()['port']);
        $client->set(['timeout' => 10]);
        Assert::true($client->connect());
        go(function () use ($client) {
            while ($client->recv(-1)) {
            }
        });

        $request         = new Request();
        $request->method = 'POST';
        $data            = str_repeat('A', 8 * 1024 * 1024);
        $result          = new Channel(1);
        go(function () use ($client, $method, $request, $data, $result) {
            if ($method === 'send') {
                $request->data = $data;
                $result->push($client->send($request));
            } else {
                $request->pipeline = true;
                Assert::same($client->send($request), 1);
                $result->push($client->write(1, $data, true));
            }
        });

        // The reader handles the reset while the data waits, which deletes stream 1.
        for ($i = 0; $i < 500 && $client->stats('active_stream_num') > 0; $i++) {
            Coroutine::sleep(0.01);
        }
        Assert::same($client->stats('active_stream_num'), 0);
        $drain->push(true);
        Assert::same($result->pop(), $method === 'send' ? 1 : true);
        $client->close();
        $listener->close();
    });
}
echo "DONE\n";
?>
--EXPECT--
DONE
