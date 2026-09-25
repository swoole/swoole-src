--TEST--
swoole_http2_server: parse large request paths without fixed scratch storage
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

function hpack_integer(int $value, int $prefixBits, int $firstByte = 0): string
{
    $prefixMax = (1 << $prefixBits) - 1;
    if ($value < $prefixMax) {
        return chr($firstByte | $value);
    }

    $encoded = chr($firstByte | $prefixMax);
    $value -= $prefixMax;
    while ($value >= 128) {
        $encoded .= chr(($value % 128) | 0x80);
        $value = intdiv($value, 128);
    }

    return $encoded . chr($value);
}

function hpack_string(string $value): string
{
    return hpack_integer(strlen($value), 7) . $value;
}

function hpack_zero_path(int $length): string
{
    $bits = '011000' . str_repeat('00000', $length) . '1111111100';
    $bits .= str_repeat('1', (8 - strlen($bits) % 8) % 8);

    $encoded = '';
    foreach (str_split($bits, 8) as $byte) {
        $encoded .= chr(bindec($byte));
    }

    return hpack_integer(strlen($encoded), 7, 0x80) . $encoded;
}

function http2_request_headers(int $pathLength): string
{
    return "\x82\x86"
        . hpack_integer(1, 4) . hpack_string('localhost')
        . hpack_integer(4, 4) . hpack_zero_path($pathLength);
}

$pm = new ProcessManager;
$pathLength = 100000;

$pm->parentFunc = function () use ($pm, $pathLength) {
    $client = new Swoole\Client(SWOOLE_SOCK_TCP);
    $client->set(['timeout' => 2]);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort()));

    $preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    Assert::same($client->send($preface), strlen($preface));
    $settings = http2_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 0, 0);
    Assert::same($client->send($settings), strlen($settings));
    $headers = http2_frame(
        SWOOLE_HTTP2_TYPE_HEADERS,
        HTTP2_FLAG_END_HEADERS | HTTP2_FLAG_END_STREAM,
        1,
        http2_request_headers($pathLength)
    );
    Assert::same($client->send($headers), strlen($headers));

    $response = '';
    while (($data = $client->recv()) !== '' && $data !== false) {
        $response .= $data;
        if (str_contains($response, '100001:')) {
            break;
        }
    }

    Assert::contains($response, '100001:');
    $client->close();
    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'open_http2_protocol' => true,
        'log_file' => '/dev/null',
    ]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end(strlen($request->server['request_uri']) . ':' . $request->server['query_string']);
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
