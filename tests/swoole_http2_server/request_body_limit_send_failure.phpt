--TEST--
swoole_http2_server: close the connection when the 413 for a request over the body limit can't be sent
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Socket;

function http2_frame(int $type, int $flags, int $streamId, string $payload = ''): string
{
    return substr(pack('N', strlen($payload)), 1) . chr($type) . chr($flags) . pack('N', $streamId) . $payload;
}

function http2_read_frame(Socket $socket, string &$buffer): ?array
{
    while (strlen($buffer) < 9 || strlen($buffer) < 9 + unpack('N', "\0" . substr($buffer, 0, 3))[1]) {
        $data = $socket->recv(65536, 5);
        if (!$data) {
            return null;
        }
        $buffer .= $data;
    }
    $length = unpack('N', "\0" . substr($buffer, 0, 3))[1];
    $frame = [ord($buffer[3]), unpack('N', substr($buffer, 5, 4))[1]];
    $buffer = substr($buffer, 9 + $length);
    return $frame;
}

$pm = new ProcessManager();
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $headers = "\x83\x86\x01\x09localhost\x04\x07/upload";
        $cases = [
            // content-length over the limit
            [http2_frame(1, 4, 1, $headers . "\x0f\x0d\x06100000")],
            // DATA over the limit, the rest sent once the server has returned the connection and stream credit for the
            // first 50000 bytes
            [
                http2_frame(1, 4, 1, $headers) . str_repeat(http2_frame(0, 0, 1, str_repeat('a', 12500)), 4),
                http2_frame(0, 0, 1, str_repeat('a', 16000)),
            ],
        ];
        foreach ($cases as $requests) {
            $socket = new Socket(AF_INET, SOCK_STREAM, 0);
            Assert::true($socket->connect('127.0.0.1', $pm->getFreePort(), 2));
            $data = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" . http2_frame(4, 0, 0) . array_shift($requests);
            Assert::same($socket->sendAll($data), strlen($data));
            $buffer = '';
            if ($requests) {
                $updates = [];
                while (count($updates) < 2 && ($frame = http2_read_frame($socket, $buffer))) {
                    if ($frame[0] === 8) {
                        $updates[$frame[1]] = true;
                    }
                }
                Assert::same(count($updates), 2);
                Assert::same($socket->sendAll($requests[0]), strlen($requests[0]));
            }
            // The 413 is larger than output_buffer_size, so the worker can't send it. The connection closes instead of
            // continuing with a header block the client never received.
            do {
                $data = $socket->recv(65536, 5);
            } while (is_string($data) && $data !== '');
            Assert::same($data, '');
            $socket->close();
        }
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1,
        'open_http2_protocol' => true,
        'package_max_length' => 64 * 1024,
        'output_buffer_size' => 32,
        'log_file' => '/dev/null',
    ]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Request', function ($request, $response) {
        $response->end('unexpected');
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
