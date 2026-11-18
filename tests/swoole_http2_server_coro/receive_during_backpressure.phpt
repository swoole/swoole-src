--TEST--
swoole_http2_server_coro: keep reading while a response waits for the client
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Socket;

const BODY_SIZE = 16 * 1024 * 1024;
const WINDOW_SIZE = 20 * 1024 * 1024;
const FRAME_SIZE = 16384;
const HTTP2_FLAG_ACK = 0x1;
const HTTP2_FLAG_END_STREAM = 0x1;
const HTTP2_FLAG_END_HEADERS = 0x4;
const HTTP2_SETTINGS_INIT_WINDOW_SIZE = 0x4;

function http2_request(int $streamId, string $method, string $path, bool $endStream): string
{
    // HPACK static table entries for :method and :scheme http, then literal :authority and :path
    $block = ($method === 'GET' ? "\x82" : "\x83") . "\x86\x01\x09localhost\x04" . chr(strlen($path)) . $path;
    $flags = HTTP2_FLAG_END_HEADERS | ($endStream ? HTTP2_FLAG_END_STREAM : 0);
    return http2_test_frame(SWOOLE_HTTP2_TYPE_HEADERS, $flags, $streamId, $block);
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
    $frame = [ord($buffer[3]), ord($buffer[4]), unpack('N', substr($buffer, 5, 4))[1], substr($buffer, 9, $length)];
    $buffer = substr($buffer, 9 + $length);
    return $frame;
}

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Coroutine\run(function () use ($pm) {
        // A small receive buffer, so /big fills the connection while the client isn't reading
        $socket = new Socket(AF_INET, SOCK_STREAM, 0);
        Assert::true($socket->setOption(SOL_SOCKET, SO_RCVBUF, 4096));
        Assert::true($socket->connect('127.0.0.1', $pm->getFreePort(), 2));
        $data = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            . http2_test_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 0, 0, pack('nN', HTTP2_SETTINGS_INIT_WINDOW_SIZE, 0x7fffffff))
            . http2_test_frame(SWOOLE_HTTP2_TYPE_WINDOW_UPDATE, 0, 0, pack('N', 0x7fff0000))
            . http2_request(1, 'POST', '/upload', false)
            . http2_test_frame(SWOOLE_HTTP2_TYPE_DATA, 0, 1, str_repeat('B', FRAME_SIZE));
        Assert::same($socket->sendAll($data), strlen($data));

        // The connection window starts at 65535; reading the first DATA frame makes the server raise it
        $buffer = '';
        $streamWindow = $connectionWindow = null;
        while (($streamWindow === null || $connectionWindow === null) && ($frame = http2_read_frame($socket, $buffer))) {
            [$type, $flags, $streamId, $payload] = $frame;
            if ($type === SWOOLE_HTTP2_TYPE_SETTINGS && !($flags & HTTP2_FLAG_ACK)) {
                $streamWindow = 65535;
                foreach (str_split($payload, 6) as $setting) {
                    ['id' => $id, 'value' => $value] = unpack('nid/Nvalue', $setting);
                    if ($id === HTTP2_SETTINGS_INIT_WINDOW_SIZE) {
                        $streamWindow = $value;
                    }
                }
            } elseif ($type === SWOOLE_HTTP2_TYPE_WINDOW_UPDATE && $streamId === 0) {
                $connectionWindow = 65535 - FRAME_SIZE + unpack('N', $payload)[1];
            }
        }
        Assert::same($streamWindow, WINDOW_SIZE);
        Assert::same($connectionWindow, WINDOW_SIZE);

        $data = http2_test_frame(SWOOLE_HTTP2_TYPE_SETTINGS, HTTP2_FLAG_ACK, 0) . http2_request(3, 'GET', '/big', true);
        Assert::same($socket->sendAll($data), strlen($data));
        Coroutine::sleep(0.3);

        // The server answers these while /big waits: /noend's handler leaves its response to the destructor,
        // the PING needs an ACK, and the rest of the upload makes the server update both windows.
        $data = http2_request(5, 'GET', '/noend', true) . http2_test_frame(SWOOLE_HTTP2_TYPE_PING, 0, 0, 'ABCDEFGH');
        $chunks = str_split(str_repeat('B', BODY_SIZE - FRAME_SIZE), FRAME_SIZE);
        foreach ($chunks as $i => $chunk) {
            $flags = $i === count($chunks) - 1 ? HTTP2_FLAG_END_STREAM : 0;
            $data .= http2_test_frame(SWOOLE_HTTP2_TYPE_DATA, $flags, 1, $chunk);
        }
        Assert::same($socket->sendAll($data, 5), strlen($data));

        $bodies = [1 => '', 3 => ''];
        $frames = [];
        while (!isset($frames['1 end'], $frames['3 end'], $frames['5 headers'], $frames['ping']) &&
               ($frame = http2_read_frame($socket, $buffer))) {
            [$type, $flags, $streamId, $payload] = $frame;
            switch ($type) {
                case SWOOLE_HTTP2_TYPE_DATA:
                    $bodies[$streamId] .= $payload;
                    break;
                case SWOOLE_HTTP2_TYPE_HEADERS:
                    $frames["{$streamId} headers"] = $payload;
                    break;
                case SWOOLE_HTTP2_TYPE_PING:
                    Assert::same($flags, HTTP2_FLAG_ACK);
                    Assert::same($payload, 'ABCDEFGH');
                    $frames['ping'] = true;
                    continue 2;
                case SWOOLE_HTTP2_TYPE_WINDOW_UPDATE:
                    $frames["{$streamId} window"] = true;
                    break;
            }
            if ($flags & HTTP2_FLAG_END_STREAM) {
                $frames["{$streamId} end"] = true;
            }
        }
        $socket->close();

        Assert::true($bodies[3] === str_repeat('A', BODY_SIZE));
        // Indexed :status 500
        Assert::same($frames['5 headers'][0] ?? null, "\x8e");
        Assert::true(isset($frames['ping'], $frames['5 end'], $frames['0 window'], $frames['1 window']));
        Assert::same($bodies[1], (string) BODY_SIZE);
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    Coroutine::set(['http2_init_window_size' => WINDOW_SIZE]);
    Coroutine\run(function () use ($pm) {
        $http = new Swoole\Coroutine\Http\Server('127.0.0.1', $pm->getFreePort());
        $http->set([
            'open_http2_protocol' => true,
            'http_compression' => false,
            'package_max_length' => 2 * BODY_SIZE,
        ]);
        $http->handle('/', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
            switch ($request->server['request_uri']) {
                case '/big':
                    // Small DATA frames are built in the socket's write buffer, which then holds the unsent bytes
                    for ($sent = 0; $sent < BODY_SIZE; $sent += 4000) {
                        $response->write(str_repeat('A', min(4000, BODY_SIZE - $sent)));
                    }
                    $response->end();
                    break;
                case '/noend':
                    // Large enough to overlap /big's unsent bytes if it were built in the same buffer
                    $response->header('x-pad', str_repeat('p', 3000));
                    break;
                case '/upload':
                    $response->end((string) strlen($request->getContent()));
                    break;
            }
        });
        $pm->wakeup();
        $http->start();
    });
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
