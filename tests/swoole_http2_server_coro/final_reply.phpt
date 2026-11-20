--TEST--
swoole_http2_server_coro: send the final reply before closing the connection
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Socket;

const FRAME_NAMES = [SWOOLE_HTTP2_TYPE_HEADERS => 'HEADERS', SWOOLE_HTTP2_TYPE_GOAWAY => 'GOAWAY'];

function connect_and_send(int $port, string $request): Socket
{
    $socket = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($socket->connect('127.0.0.1', $port, 2));
    $data = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" . http2_test_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 0, 0)
        . http2_test_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 0x1, 0) . $request;
    Assert::same($socket->sendAll($data), strlen($data));
    return $socket;
}

// Returns stream $id's frames up to the first one of $type.
function read_stream(Socket $socket, int $id, int $type): array
{
    $frames = [];
    do {
        $header = $socket->recvAll(9, 5);
        Assert::same(strlen($header), 9);
        $length = unpack('N', "\0" . substr($header, 0, 3))[1];
        $payload = $length === 0 ? '' : $socket->recvAll($length, 5);
        Assert::same(strlen($payload), $length);
        if ((unpack('N', substr($header, 5, 4))[1] & 0x7FFFFFFF) === $id) {
            $frames[] = [ord($header[3]), ord($header[4]), $payload];
        }
    } while (!$frames || end($frames)[0] !== $type);
    return $frames;
}

$port = get_one_free_port();
Coroutine\run(function () use ($port) {
    $http = new Swoole\Coroutine\Http\Server('127.0.0.1', $port);
    $http->set(['open_http2_protocol' => true, 'package_max_length' => 1024]);
    $http->handle('/', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        if ($request->server['request_uri'] === '/after-reset') {
            $response->end('OK');
            return;
        }
        // The receive loop ends the response in the destructor, then closes the connection
        $response->goaway();
    });
    Coroutine::create(fn () => $http->start());

    // A Content-Length over package_max_length is answered with 413 and RST_STREAM(NO_ERROR), and the connection
    // stays open
    $upload = "\x83\x86\x01\x09localhost\x04\x07/upload\x5c\x044096";
    $socket = connect_and_send($port, http2_test_frame(SWOOLE_HTTP2_TYPE_HEADERS, 0x4, 1, $upload));
    $frames = read_stream($socket, 1, SWOOLE_HTTP2_TYPE_RST_STREAM);
    Assert::same(count($frames), 2);
    Assert::same([$frames[0][0], $frames[0][1]], [SWOOLE_HTTP2_TYPE_HEADERS, 0x5]);
    Assert::same(substr($frames[0][2], 0, 5), "\x48\x03413");
    Assert::same($frames[1][2], pack('N', SWOOLE_HTTP2_ERROR_NO_ERROR));
    $request = http2_test_request_headers(3, '/after-reset');
    Assert::same($socket->sendAll($request), strlen($request));
    $frames = read_stream($socket, 3, SWOOLE_HTTP2_TYPE_DATA);
    Assert::same(count($frames), 2);
    Assert::same([$frames[0][0], $frames[0][2][0]], [SWOOLE_HTTP2_TYPE_HEADERS, "\x88"]);
    Assert::same([$frames[1][1], $frames[1][2]], [0x1, 'OK']);
    $socket->close();

    $socket = connect_and_send($port, http2_test_frame(SWOOLE_HTTP2_TYPE_HEADERS, 0x5, 1, "\x82\x86\x01\x09localhost\x84"));
    $buffer = '';
    while (is_string($received = $socket->recv(65536, 5)) && $received !== '') {
        $buffer .= $received;
    }
    // The server closed the connection
    Assert::same($received, '');
    $frames = [];
    while ($buffer !== '') {
        $length = unpack('N', "\0" . substr($buffer, 0, 3))[1];
        Assert::greaterThanEq(strlen($buffer), 9 + $length);
        $type = ord($buffer[3]);
        if (isset(FRAME_NAMES[$type])) {
            $frames[] = FRAME_NAMES[$type] . ' flags=' . ord($buffer[4]) . ' stream=' . unpack('N', substr($buffer, 5, 4))[1];
        }
        $buffer = substr($buffer, 9 + $length);
    }
    echo implode(', ', $frames), "\n";
    $socket->close();
    $http->shutdown();
});
?>
--EXPECT--
GOAWAY flags=0 stream=0, HEADERS flags=5 stream=1
