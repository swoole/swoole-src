--TEST--
swoole_http_client_coro: write_func receives decompressed body
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_extension_not_exist('zlib');
skip_if_not_defined('SWOOLE_HAVE_ZLIB');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;

Coroutine\run(function () {
    $server = new Server('127.0.0.1', 0);
    $data = base64_encode(random_bytes(256 * 1024));
    $server->handle('/', function ($request, $response) use ($data) {
        $response->end($data);
    });
    $received = new Coroutine\Channel(1);
    $server->handle('/sse', function ($request, $response) use ($received) {
        $encoding = $request->header['accept-encoding'];
        $context = deflate_init($encoding === 'gzip' ? ZLIB_ENCODING_GZIP : ZLIB_ENCODING_DEFLATE);
        $response->header('Content-Type', 'text/event-stream');
        $response->header('Content-Encoding', $encoding);
        for ($i = 0; $i < 8; $i++) {
            $response->write(deflate_add($context, "data: {$i}\n\n", ZLIB_SYNC_FLUSH));
            if ($received->pop(5) !== $i) {
                break;
            }
        }
        $response->write(deflate_add($context, '', ZLIB_FINISH));
        $response->end();
    });
    $cid = Coroutine::create(fn () => $server->start());
    try {
        $encodings = ['gzip', 'deflate'];
        if (defined('SWOOLE_HAVE_BROTLI')) {
            $encodings[] = 'br';
        }
        foreach ($encodings as $encoding) {
            $body = '';
            $client = new Client('127.0.0.1', $server->port);
            $client->setHeaders(['Accept-Encoding' => $encoding]);
            $client->set(['timeout' => 5, 'write_func' => function ($client, $chunk) use (&$body) {
                $body .= $chunk;
            }]);
            Assert::true($client->get('/'));
            Assert::same($client->headers['content-encoding'], $encoding);
            Assert::same($body, $data);
            Assert::same($client->body, '');
            $client->close();
        }
        foreach (['gzip', 'deflate'] as $encoding) {
            $buffer = '';
            $events = [];
            $client = new Client('127.0.0.1', $server->port);
            $client->setHeaders(['Accept-Encoding' => $encoding]);
            $client->set(['timeout' => 10, 'write_func' => function ($client, $chunk) use (&$buffer, &$events, $received) {
                $buffer .= $chunk;
                while (($pos = strpos($buffer, "\n\n")) !== false) {
                    $events[] = substr($buffer, 0, $pos);
                    $buffer = substr($buffer, $pos + 2);
                    $received->push(count($events) - 1);
                }
            }]);
            Assert::true($client->get('/sse'));
            Assert::same($client->headers['content-encoding'], $encoding);
            Assert::same($events, array_map(fn ($i) => "data: {$i}", range(0, 7)));
            Assert::same($buffer, '');
            $client->close();
        }
    } finally {
        // Drain accepted connections before releasing the listener's callback on stable branches.
        $handlers = array_values(array_diff(iterator_to_array(Coroutine::list()), [Coroutine::getCid(), $cid]));
        if ($handlers) {
            Assert::true(Coroutine::join($handlers, 3));
        }
        $server->shutdown();
        Coroutine::join([$cid]);
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
