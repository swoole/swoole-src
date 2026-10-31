--TEST--
swoole_http2_server: split response data by the peer frame limit
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const HTTP2_FLAG_END_STREAM = 0x1;
const HTTP2_FLAG_END_HEADERS = 0x4;

function http2_frame(int $type, int $flags, int $streamId, string $payload = ''): string
{
    return substr(pack('N', strlen($payload)), 1)
        . chr($type)
        . chr($flags)
        . pack('N', $streamId & 0x7fffffff)
        . $payload;
}

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm) {
    $client = new Swoole\Client(SWOOLE_SOCK_TCP);
    $client->set(['timeout' => 2]);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));

    $preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    $settings = http2_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 0, 0, pack('nN', 5, 16384));
    $headers = http2_frame(
        SWOOLE_HTTP2_TYPE_HEADERS,
        HTTP2_FLAG_END_HEADERS | HTTP2_FLAG_END_STREAM,
        1,
        "\x82\x86\x84\x01\x09localhost"
    );
    $request = $preface . $settings . $headers;
    Assert::same($client->send($request), strlen($request));

    $buffer = '';
    $dataLengths = [];
    $complete = false;
    while (!$complete && ($data = $client->recv()) !== '' && $data !== false) {
        $buffer .= $data;
        while (strlen($buffer) >= 9) {
            $length = unpack('N', "\0" . substr($buffer, 0, 3))[1];
            if (strlen($buffer) < 9 + $length) {
                break;
            }

            $type = ord($buffer[3]);
            $flags = ord($buffer[4]);
            $streamId = unpack('N', substr($buffer, 5, 4))[1] & 0x7fffffff;
            $buffer = substr($buffer, 9 + $length);

            if ($type === SWOOLE_HTTP2_TYPE_DATA && $streamId === 1) {
                $dataLengths[] = $length;
                $complete = ($flags & HTTP2_FLAG_END_STREAM) !== 0;
            }
        }
    }

    Assert::same($dataLengths, [16384, 16384, 7232]);
    $client->close();
    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'open_http2_protocol' => true,
        'http2_max_frame_size' => 65536,
        'log_file' => '/dev/null',
    ]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end(str_repeat('a', 40000));
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
