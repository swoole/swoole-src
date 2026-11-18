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

$port = get_one_free_port();
Coroutine\run(function () use ($port) {
    $http = new Swoole\Coroutine\Http\Server('127.0.0.1', $port);
    $http->set(['open_http2_protocol' => true, 'package_max_length' => 1024]);
    $http->handle('/', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        // The receive loop ends the response in the destructor, then closes the connection
        $response->goaway();
    });
    Coroutine::create(fn () => $http->start());

    $requests = [
        // A Content-Length over package_max_length is answered with 413 and GOAWAY
        http2_test_frame(SWOOLE_HTTP2_TYPE_HEADERS, 0x4, 1, "\x83\x86\x01\x09localhost\x04\x07/upload\x5c\x044096"),
        http2_test_frame(SWOOLE_HTTP2_TYPE_HEADERS, 0x5, 1, "\x82\x86\x01\x09localhost\x84"),
    ];
    foreach ($requests as $request) {
        $socket = new Socket(AF_INET, SOCK_STREAM, 0);
        Assert::true($socket->connect('127.0.0.1', $port, 2));
        $data = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" . http2_test_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 0, 0)
            . http2_test_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 0x1, 0) . $request;
        Assert::same($socket->sendAll($data), strlen($data));
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
    }
    $http->shutdown();
});
?>
--EXPECT--
HEADERS flags=5 stream=1, GOAWAY flags=0 stream=0
GOAWAY flags=0 stream=0, HEADERS flags=5 stream=1
