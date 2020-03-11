--TEST--
swoole_socket_coro: server accept
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Socket;

class Protocol
{
    const HEAD_LENGTH = 4 + 2 + 4;
    const LENGTH_OFFSET = 6;
    const HEAD_PACK_FORMAT = 'nNN';
    const HEAD_UNPACK_FORMAT = 'ntype/Nid/Nlength';

    public static function pack(int $type, int $id, string $data): string
    {
        return pack(static::HEAD_PACK_FORMAT, $type, $id, strlen($data)) . $data;
    }

    public static function unpack(string $data): array
    {
        return unpack(static::HEAD_UNPACK_FORMAT, $data);
    }
}

Co\run(function () {
    $server = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    $server->setProtocol([
        'open_length_check' => true,
        'package_length_type' => 'N',
        'package_length_offset' => Protocol::LENGTH_OFFSET,
        'package_body_offset' => Protocol::HEAD_LENGTH
    ]);
    if (!$server->bind('127.0.0.1')) {
        throw new Exception('Bind failed: ' . $server->errMsg);
    }
    if (!$server->listen()) {
        throw new Exception('Listen failed: ' . $server->errMsg);
    }
    $port = $server->getsockname()['port'] ?? 0;
    if (!$port) {
        throw new Exception('No port');
    }
    for ($n = MAX_CONCURRENCY; $n--;) {
        Coroutine::create(function () use ($port) {
            Co::sleep(0.01);
            $client = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
            $connected = $client->connect('127.0.0.1', $port, 3);
            if (!$connected) {
                throw new Exception('Connect failed: ' . $client->errMsg);
            }
            for ($n = MAX_REQUESTS; $n--;) {
                $bytes = mt_rand(2, 1024);
                $random = $bytes ? get_safe_random($bytes - 1) . 'S' : '';
                $data = Protocol::pack(mt_rand(0, 127), mt_rand(0, 4294967295), $random);
                if ($client->sendAll($data) !== strlen($data)) {
                    throw new Exception('Send failed: ' . $client->errMsg);
                }
                $head = $client->recvAll(Protocol::HEAD_LENGTH);
                if (strlen($head) !== Protocol::HEAD_LENGTH) {
                    throw new Exception('Recv head failed: ' . $client->errMsg);
                }
                $head = Protocol::unpack($head);
                $length = $head['length'];
                if ($length !== 0) {
                    $body = $client->recvAll($length, -1);
                    if (strlen($body) !== $length) {
                        throw new Exception('Recv body failed: ' . $client->errMsg);
                    }
                    if (Assert::same($body[strlen($body) - 1], 'W')) {
                        $body[strlen($body) - 1] = 'S';
                    }
                    Assert::same($body, $random);
                }
            }
            $client->close();
        });
    }
    Coroutine::create(function () use ($server) {
        while (true) {
            Coroutine::sleep(0.1);
            if (Coroutine::stats()['coroutine_num'] === 2) {
                $server->close();
                break;
            }
        }
    });
    while (true) {
        /* @var $client Socket */
        $client = $server->accept(-1);
        if (!$client) {
            break;
        }
        go(function () use ($client) {
            while (true) {
                $packet = $client->recvPacket(-1);
                if (!$packet) {
                    /* Connection closed */
                    break;
                }
                if (strlen($packet) > Protocol::HEAD_LENGTH) {
                    Assert::same($packet[strlen($packet) - 1], 'S');
                    $packet[strlen($packet) - 1] = 'W';
                }
                $client->sendAll($packet);
            }
        });
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
