--TEST--
swoole_http_client_coro: write_func receives decompressed body
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
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
    Coroutine::create(fn () => $server->start());
    try {
        foreach (['gzip', 'deflate', 'br'] as $encoding) {
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
    } finally {
        $server->shutdown();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
