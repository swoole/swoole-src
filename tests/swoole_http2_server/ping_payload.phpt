--TEST--
swoole_http2_server: echo PING payloads and reject PING frames of the wrong length
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Socket;

const HTTP2_FLAG_ACK = 0x1;
const HTTP2_FLAG_END_STREAM = 0x1;
const HTTP2_FLAG_END_HEADERS = 0x4;
const HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

function http2_frame(int $type, int $flags, int $streamId, string $payload = ''): string
{
    return substr(pack('N', strlen($payload)), 1)
        . chr($type)
        . chr($flags)
        . pack('N', $streamId & 0x7fffffff)
        . $payload;
}

function http2_connect(int $port, string $frames): Socket
{
    $socket = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($socket->connect('127.0.0.1', $port, 1));
    $data = HTTP2_PREFACE . http2_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 0, 0) . $frames;
    Assert::same($socket->sendAll($data), strlen($data));
    return $socket;
}

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
        $ping = http2_frame(SWOOLE_HTTP2_TYPE_PING, 0, 0, 'ABCDEFGH');
        $invalidFrames = [
            http2_frame(SWOOLE_HTTP2_TYPE_PING, 0, 0),
            http2_frame(SWOOLE_HTTP2_TYPE_PING, 0, 0, 'ABCDEFGHI'),
            http2_frame(SWOOLE_HTTP2_TYPE_PING, HTTP2_FLAG_ACK, 0, 'ABCDEFG'),
        ];
        foreach ($invalidFrames as $frame) {
            $socket = http2_connect($pm->getFreePort(), $ping . $frame);
            $received = '';
            while (($data = $socket->recv(65535, 2)) !== '' && $data !== false) {
                $received .= $data;
            }
            $socket->close();
            Assert::same($data, '');
            Assert::same(substr_count($received, "\0\0\x08" . chr(SWOOLE_HTTP2_TYPE_PING) . chr(HTTP2_FLAG_ACK)), 1);
            Assert::contains($received, http2_frame(SWOOLE_HTTP2_TYPE_PING, HTTP2_FLAG_ACK, 0, 'ABCDEFGH'));
        }

        // HPACK static table entries for :method GET, :path / and :scheme http
        $request = http2_frame(SWOOLE_HTTP2_TYPE_HEADERS, HTTP2_FLAG_END_STREAM | HTTP2_FLAG_END_HEADERS, 1, "\x82\x84\x86");
        $socket = http2_connect($pm->getFreePort(), $request);
        $response = http2_frame(SWOOLE_HTTP2_TYPE_DATA, HTTP2_FLAG_END_STREAM, 1, 'ok');
        $received = '';
        while (!str_contains($received, $response) && ($data = $socket->recv(65535, 2))) {
            $received .= $data;
        }
        $socket->close();
        Assert::contains($received, $response);
        Assert::contains($received, http2_frame(SWOOLE_HTTP2_TYPE_PING, 0, 0, str_repeat("\0", 8)));
    });

    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        Assert::true($response->ping());
        $response->end('ok');
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
