--TEST--
swoole_http2_server: send header blocks in encoding order while one waits for output buffer space
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('sockets');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http2_raw_client.php';

use Swoole\Coroutine;
use Swoole\Event;
use Swoole\Timer;

const BUFFER_SIZE = 64 * 1024;

// Stream 1's HEADERS wait for output buffer space. The client then reads until the server accepts new sends again
// while stream 1's HEADERS still wait. Returns the client and the bytes it has read.
function wait_with_headers_pending(ProcessManager $pm): array
{
    // Small buffers, so the server's output fills while the client isn't reading
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    Assert::true(socket_set_option($socket, SOL_SOCKET, SO_RCVBUF, 4096));
    Assert::true(socket_connect($socket, '127.0.0.1', $pm->getFreePort()));
    $client = socket_export_stream($socket);
    stream_set_timeout($client, 5);
    $data = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" . http2_test_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 0, 0)
        . http2_test_request_headers(1, '/a');
    Assert::same(fwrite($client, $data), strlen($data));
    Assert::true($pm->wait());
    $read = http2_test_read_exact($client, BUFFER_SIZE);
    Assert::true($pm->wait());
    return [$client, $read];
}

// Parses the output from the start. Returns the stream IDs of the HEADERS frames in arrival order, and whether both
// streams ended before the connection closed.
function read_header_order($client, string $buffer): array
{
    $order = [];
    $ended = [];
    while (count($ended) < 2) {
        if (strlen($buffer) >= 9 && strlen($buffer) >= 9 + ($length = unpack('N', "\0" . substr($buffer, 0, 3))[1])) {
            $type = ord($buffer[3]);
            $id = unpack('N', substr($buffer, 5, 4))[1] & 0x7FFFFFFF;
            if ($type === SWOOLE_HTTP2_TYPE_HEADERS) {
                $order[] = $id;
            }
            if (in_array($type, [SWOOLE_HTTP2_TYPE_DATA, SWOOLE_HTTP2_TYPE_HEADERS], true) && (ord($buffer[4]) & 0x1)) {
                $ended[$id] = true;
            }
            $buffer = substr($buffer, 9 + $length);
            continue;
        }
        $data = @fread($client, 65536);
        if ($data === false || $data === '') {
            Assert::false(stream_get_meta_data($client)['timed_out']);
            break;
        }
        $buffer .= $data;
    }
    return [$order, count($ended) === 2];
}

$pm = new ProcessManager();
$pm->parentFunc = function () use ($pm) {
    try {
        // Stream 1's trailers follow stream 3's HEADERS without another full buffer
        [$client, $read] = wait_with_headers_pending($pm);
        $request = http2_test_request_headers(3, '/b');
        Assert::same(fwrite($client, $request), strlen($request));
        Assert::true($pm->wait());
        Assert::same(read_header_order($client, $read), [[1, 3, 1], true]);
        fclose($client);
        Assert::true($pm->wait());

        // A 413 from the request parser can't wait for its turn, so the connection closes
        [$client, $read] = wait_with_headers_pending($pm);
        $upload = http2_test_frame(SWOOLE_HTTP2_TYPE_HEADERS, 0x4, 3, "\x83\x86\x01\x09localhost\x04\x07/upload\x5c\x06131072");
        Assert::same(fwrite($client, $upload), strlen($upload));
        // Reading before the server closes could empty the buffer and let stream 1's HEADERS go first
        Assert::true($pm->wait());
        Assert::same(read_header_order($client, $read), [[], false]);
        fclose($client);

        // Canceling a header block that waits for its turn closes the connection
        [$client, $read] = wait_with_headers_pending($pm);
        $request = http2_test_request_headers(3, '/canceled');
        Assert::same(fwrite($client, $request), strlen($request));
        Assert::true($pm->wait());
        Assert::same(read_header_order($client, $read), [[], false]);
        fclose($client);
    } finally {
        $pm->kill();
    }
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'http_compression' => false,
        'package_max_length' => 64 * 1024,
        'send_yield' => true,
        'socket_buffer_size' => BUFFER_SIZE,
        'kernel_socket_send_buffer_size' => 4096,
    ]);
    $server->on('WorkerStart', fn () => $pm->wakeup());
    $server->on('Close', fn () => $pm->wakeup());
    $server->on('Request', function ($request, $response) use ($pm, $server) {
        switch ($request->server['request_uri']) {
            case '/a':
                http2_test_fill_send_buffer($server, $request->fd);
                Event::defer(function () use ($pm, $server, $request) {
                    $pm->wakeup();
                    // New sends are accepted below the limit, while HEADERS waiting for space resume only once empty
                    Timer::tick(1, function ($timer) use ($pm, $server, $request) {
                        $queued = $server->getClientInfo($request->fd)['send_queued_bytes'] ?? 0;
                        if ($queued > 0 && $queued < BUFFER_SIZE) {
                            Timer::clear($timer);
                            $pm->wakeup();
                        }
                    });
                });
                $response->trailer('x-trailer', 'a');
                $response->end('A');
                break;
            case '/b':
                Event::defer(fn () => $pm->wakeup());
                Assert::true($response->end('B'));
                break;
            case '/canceled':
                $cid = Coroutine::getCid();
                Event::defer(fn () => Coroutine::cancel($cid));
                Assert::false($response->end('C'));
                Assert::same(swoole_last_error(), SWOOLE_ERROR_CO_CANCELED);
                break;
        }
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
