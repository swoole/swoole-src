--TEST--
swoole_http2_server_coro: keep reading while responses wait for the client
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Socket;

const BODY_SIZE = 4 * 1024 * 1024;
const WINDOW_SIZE = 5 * 1024 * 1024;
const FRAME_SIZE = 16384;
const PING_COUNT = 100;
const CHUNK_SIZE = 4000;
const HTTP2_FLAG_ACK = 0x1;
const HTTP2_FLAG_END_STREAM = 0x1;
const HTTP2_FLAG_END_HEADERS = 0x4;
const HTTP2_SETTINGS_INIT_WINDOW_SIZE = 0x4;
const HTTP2_SETTINGS_MAX_FRAME_SIZE = 0x5;
// Once encoded, more than the connection holds
define('HEADER_LARGE', base64_encode(random_bytes(3 * 1024 * 1024)));

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

// Starts an upload on stream 1 and gets the credit to send the rest of it without reading again
function http2_open(int $port, bool $ssl, string &$buffer): Socket
{
    // Small buffers, so the server's output fills the connection while the client isn't reading, and the upload
    // stops when the server stops reading
    $socket = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($socket->setOption(SOL_SOCKET, SO_RCVBUF, 4096));
    Assert::true($socket->setOption(SOL_SOCKET, SO_SNDBUF, 4096));
    if ($ssl) {
        $socket->setProtocol(['open_ssl' => true]);
    }
    Assert::true($socket->connect('127.0.0.1', $port, 2));
    $settings = pack('nN', HTTP2_SETTINGS_INIT_WINDOW_SIZE, 0x7fffffff) . pack('nN', HTTP2_SETTINGS_MAX_FRAME_SIZE, 0xffffff);
    $data = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        . http2_test_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 0, 0, $settings)
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
    return $socket;
}

// Connections inherit the listening socket's buffer sizes, so the server's side of the connection is small too
function http2_pin_server_buffers(Swoole\Coroutine\Http\Server $http): void
{
    if (PHP_OS_FAMILY === 'Windows') {
        return;
    }
    $socket = Socket::import(fopen("php://fd/{$http->fd}", 'r'));
    Assert::true($socket->setOption(SOL_SOCKET, SO_SNDBUF, 4096));
    Assert::true($socket->setOption(SOL_SOCKET, SO_RCVBUF, 4096));
}

function http2_upload_rest(): string
{
    $data = '';
    $chunks = str_split(str_repeat('B', BODY_SIZE - FRAME_SIZE), FRAME_SIZE);
    foreach ($chunks as $i => $chunk) {
        $flags = $i === count($chunks) - 1 ? HTTP2_FLAG_END_STREAM : 0;
        $data .= http2_test_frame(SWOOLE_HTTP2_TYPE_DATA, $flags, 1, $chunk);
    }
    return $data;
}

function http2_pings(): string
{
    $data = '';
    for ($i = 0; $i < PING_COUNT; $i++) {
        $data .= http2_test_frame(SWOOLE_HTTP2_TYPE_PING, 0, 0, pack('J', $i));
    }
    return $data;
}

// Reads until the given streams have ended and the given number of PING ACKs have arrived
function http2_read_responses(Socket $socket, string &$buffer, array $streams, int $pings): array
{
    // A trailer is recorded by its flags
    $result = ['headers' => [], 'trailers' => [], 'bodies' => [], 'pings' => [], 'windows' => []];
    $ended = [];
    while ((count($ended) < count($streams) || count($result['pings']) < $pings) &&
           ($frame = http2_read_frame($socket, $buffer))) {
        [$type, $flags, $streamId, $payload] = $frame;
        switch ($type) {
            case SWOOLE_HTTP2_TYPE_HEADERS:
                if (isset($result['headers'][$streamId])) {
                    $result['trailers'][$streamId] = $flags;
                } else {
                    $result['headers'][$streamId] = $payload;
                }
                break;
            case SWOOLE_HTTP2_TYPE_DATA:
                $result['bodies'][$streamId] ??= '';
                $result['bodies'][$streamId] .= $payload;
                break;
            case SWOOLE_HTTP2_TYPE_PING:
                Assert::same($flags, HTTP2_FLAG_ACK);
                $result['pings'][] = $payload;
                continue 2;
            case SWOOLE_HTTP2_TYPE_WINDOW_UPDATE:
                $result['windows'][$streamId] = true;
                continue 2;
        }
        if ($flags & HTTP2_FLAG_END_STREAM) {
            $ended[$streamId] = true;
        }
    }
    ksort($ended);
    Assert::same(array_keys($ended), $streams);
    return $result;
}

$pm = new ProcessManager;
$pm->initFreePorts(2);
$pm->parentFunc = function () use ($pm) {
    Coroutine\run(function () use ($pm) {
        // A handler's response waits for the client while the client finishes its upload
        $buffer = '';
        $socket = http2_open($pm->getFreePort(0), false, $buffer);
        $data = http2_test_frame(SWOOLE_HTTP2_TYPE_SETTINGS, HTTP2_FLAG_ACK, 0) . http2_request(3, 'GET', '/big', true);
        Assert::same($socket->sendAll($data), strlen($data));
        // /big waits for the client before the receive loop reads these, so the server answers them while it waits:
        // /noend's handler leaves its response to the destructor,
        // the PING needs an ACK, and the rest of the upload makes the server update both windows.
        $data = http2_request(5, 'GET', '/noend', true) . http2_test_frame(SWOOLE_HTTP2_TYPE_PING, 0, 0, 'ABCDEFGH');
        $data .= http2_upload_rest();
        Assert::same($socket->sendAll($data, 5), strlen($data));
        $result = http2_read_responses($socket, $buffer, [1, 3, 5], 1);
        $socket->close();
        Assert::true($result['bodies'][3] !== '' && strspn($result['bodies'][3], 'A') === strlen($result['bodies'][3]));
        // Indexed :status 500
        Assert::same($result['headers'][5][0], "\x8e");
        Assert::same($result['pings'], ['ABCDEFGH']);
        Assert::true(isset($result['windows'][0], $result['windows'][1]));
        Assert::same($result['bodies'][1], (string) BODY_SIZE);

        foreach ([0 => false, 1 => true] as $port => $ssl) {
            // The receive loop's own response is more than the connection holds, with nothing else writing
            $socket = http2_open($pm->getFreePort($port), $ssl, $buffer);
            $data = http2_test_frame(SWOOLE_HTTP2_TYPE_SETTINGS, HTTP2_FLAG_ACK, 0) . http2_request(3, 'GET', '/large', true);
            $data .= http2_pings() . http2_upload_rest();
            Assert::same($socket->sendAll($data, 5), strlen($data));
            $result = http2_read_responses($socket, $buffer, [1, 3], PING_COUNT);
            Assert::greaterThan(strlen($result['headers'][3]), 2 * 1024 * 1024);
            Assert::same($result['trailers'][3] & HTTP2_FLAG_END_STREAM, HTTP2_FLAG_END_STREAM);
            Assert::same($result['pings'], array_map(fn ($i) => pack('J', $i), range(0, PING_COUNT - 1)));
            Assert::same($result['bodies'][1], (string) BODY_SIZE);
            $socket->close();
        }
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    Coroutine::set(['http2_init_window_size' => WINDOW_SIZE]);
    Coroutine\run(function () use ($pm) {
        foreach ([0 => false, 1 => true] as $port => $ssl) {
            $http = new Swoole\Coroutine\Http\Server('127.0.0.1', $pm->getFreePort($port), $ssl);
            $http->set([
                'open_http2_protocol' => true,
                'http_compression' => false,
                'package_max_length' => 2 * BODY_SIZE,
                'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
                'ssl_key_file' => SSL_FILE_DIR . '/server.key',
            ]);
            http2_pin_server_buffers($http);
            $http->handle('/', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
                switch ($request->server['request_uri']) {
                    case '/big':
                        // Small DATA frames are built in the socket's write buffer, which then holds the unsent bytes.
                        // Write until a write has to wait for the client: the callback runs once this coroutine yields.
                        $waited = false;
                        Swoole\Event::defer(function () use (&$waited) {
                            $waited = true;
                        });
                        do {
                            $ok = $response->write(str_repeat('A', CHUNK_SIZE));
                        } while ($ok && !$waited);
                        $response->end();
                        break;
                    case '/noend':
                        // Large enough to overlap /big's unsent bytes if it were built in the same buffer
                        $response->header('x-pad', str_repeat('p', 3000));
                        break;
                    case '/large':
                        // Left to the destructor, so the receive loop sends the header block and the trailer
                        $response->header('x-pad', HEADER_LARGE);
                        $response->trailer('x-trailer', 'end');
                        break;
                    case '/upload':
                        $response->end((string) strlen($request->getContent()));
                        break;
                }
            });
            Coroutine::create(fn () => $http->start());
        }
        $pm->wakeup();
    });
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
