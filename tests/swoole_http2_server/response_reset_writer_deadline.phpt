--TEST--
swoole_http2_server: a reset that finishes after the writer doesn't leave the writer's deadline behind
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
use Swoole\Coroutine\Socket;

$pm = new ProcessManager();
$pm->parentFunc = function () use ($pm) {
    try {
        // Small buffers, so the large response fills the connection while the client isn't reading
        $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        Assert::true(socket_set_option($socket, SOL_SOCKET, SO_RCVBUF, 4096));
        Assert::true(socket_connect($socket, '127.0.0.1', $pm->getFreePort()));
        $client = socket_export_stream($socket);
        stream_set_timeout($client, 5);
        $window = pack('N', 32 * 1024 * 1024);
        $data = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
            . http2_test_frame(SWOOLE_HTTP2_TYPE_SETTINGS, 0, 0, pack('nN', 4, 0))
            . http2_test_frame(SWOOLE_HTTP2_TYPE_WINDOW_UPDATE, 0, 0, $window)
            . http2_test_request_headers(1, '/writer')
            . http2_test_request_headers(3, '/large')
            . http2_test_frame(SWOOLE_HTTP2_TYPE_WINDOW_UPDATE, 0, 3, $window);
        Assert::same(fwrite($client, $data), strlen($data));
        Assert::true($pm->wait());
        Assert::same(http2_test_wait_for_frame($client, SWOOLE_HTTP2_TYPE_RST_STREAM)['streamId'], 1);
        // The server pings after the writer's deadline has passed
        http2_test_wait_for_frame($client, SWOOLE_HTTP2_TYPE_PING, 0);
        fwrite($client, http2_test_frame(SWOOLE_HTTP2_TYPE_PING, 0, 0, 'barrier!'));
        Assert::same(http2_test_wait_for_frame($client, SWOOLE_HTTP2_TYPE_PING, 1)['payload'], 'barrier!');
        fclose($client);
    } finally {
        $pm->kill();
    }
};
$pm->childFunc = function () use ($pm) {
    Coroutine\run(function () use ($pm) {
        $http = new Swoole\Coroutine\Http\Server('127.0.0.1', $pm->getFreePort());
        $http->set(['open_http2_protocol' => true, 'http_compression' => false, 'write_timeout' => 2]);
        // Connections inherit the listening socket's buffer size
        $listener = Socket::import(fopen("php://fd/{$http->fd}", 'r'));
        Assert::true($listener->setOption(SOL_SOCKET, SO_SNDBUF, 4096));
        $writer = null;
        $writerReturned = false;
        $http->handle('/', function ($request, $response) use ($pm, &$writer, &$writerReturned) {
            if ($request->server['request_uri'] === '/writer') {
                $writer = $response;
                Assert::false($response->write('NEVER'));
                $writerReturned = true;
                $pm->wakeup();
                return;
            }
            Coroutine::create(function () use (&$writer, &$writerReturned) {
                // This handler now holds the write lock on a full socket, so the reset finishes after the writer
                Coroutine::sleep(0.1);
                Assert::true($writer->reset());
                Assert::true($writerReturned);
                Coroutine::sleep(2);
                Assert::true($writer->ping());
            });
            Assert::true($response->end(str_repeat('L', 2 * 1024 * 1024)));
        });
        Swoole\Event::defer(fn () => $pm->wakeup());
        $http->start();
    });
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
