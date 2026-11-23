--TEST--
swoole_http2_client_coro: advertise connection credit separately and replenish one-byte receive windows
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

function read_frame(Swoole\Coroutine\Socket $peer): array
{
    $header = $peer->recvAll(9, 2);
    Assert::same(strlen($header), 9);
    $length = unpack('N', "\0" . substr($header, 0, 3))[1];
    return [ord($header[3]), ord($header[4]), unpack('N', substr($header, 5, 4))[1],
        $length ? $peer->recvAll($length, 2) : ''];
}

function send_frames(Swoole\Coroutine\Socket $peer, string $frames): void
{
    Assert::same($peer->sendAll($frames), strlen($frames));
}

Swoole\Coroutine\run(function () {
    foreach ([1, 131072] as $window) {
        Swoole\Coroutine::set(['http2_init_window_size' => $window]);
        $listener = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
        Assert::true($listener->bind('127.0.0.1', 0));
        Assert::true($listener->listen());
        $client = new Swoole\Coroutine\Http2\Client('127.0.0.1', $listener->getsockname()['port']);
        Assert::true($client->connect());
        $peer = $listener->accept(2);
        Assert::same($peer->recvAll(24, 2), "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
        Assert::same(read_frame($peer)[0], 4);
        if ($window > 65535) {
            Assert::same(read_frame($peer), [8, 0, 0, pack('N', $window - 65535)]);
        }
        Assert::same($client->send(new Swoole\Http2\Request()), 1);
        Assert::same(read_frame($peer)[0], 1);
        $frames = http2_test_frame(4, 0, 0) . http2_test_frame(1, 4, 1, "\x88");
        if ($window === 1) {
            send_frames($peer, $frames . http2_test_frame(0, 0, 1, 'X'));
            Assert::same($client->read(2)->data, 'X');
            do {
                $frame = read_frame($peer);
            } while ($frame[0] !== 8);
            Assert::same($frame, [8, 0, 1, pack('N', 1)]);
            send_frames($peer, http2_test_frame(0, 1, 1, 'Y'));
            Assert::same($client->read(2)->data, 'Y');
        } else {
            for ($i = 0; $i < 4; ++$i) {
                $frames .= http2_test_frame(0, $i === 3 ? 1 : 0, 1, str_repeat('A', 16384));
            }
            send_frames($peer, $frames);
            Assert::same(strlen($client->recv(2)->data), 65536);
            $updates = [];
            while (count($updates) < 2) {
                $frame = read_frame($peer);
                if ($frame[0] === 8) {
                    $updates[$frame[2]] = unpack('N', $frame[3])[1];
                }
            }
            Assert::same($updates, [0 => 65536, 1 => 65536]);
        }
        $client->close();
        $peer->close();
        $listener->close();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
