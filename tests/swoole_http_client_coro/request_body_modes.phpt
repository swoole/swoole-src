--TEST--
swoole_http_client_coro: raw, URL-encoded and multipart bodies retain their encoding rules
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;

Assert::setThrowException(true);

$filename = tempnam(sys_get_temp_dir(), 'swoole-body-modes-');
file_put_contents($filename, "disk\0content");
try {
    Coroutine\run(function () use ($filename) {
        foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $ssl) {
            $server = new Server('127.0.0.1', 0, $ssl);
            $server->set([
                'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
                'ssl_key_file' => SSL_FILE_DIR . '/server.key',
            ]);
            $server->handle('/', function ($request, $response) {
                if ($request->server['request_uri'] === '/multipart') {
                    Assert::same($request->post, ['name' => 'example']);
                    Assert::same(file_get_contents($request->files['disk']['tmp_name']), "disk\0content");
                    Assert::same(file_get_contents($request->files['memory']['tmp_name']), "memory\0content");
                    $response->end('multipart');
                } elseif ($request->server['request_uri'] === '/ignored') {
                    Assert::same($request->post ?? [], []);
                    Assert::same(file_get_contents($request->files['memory']['tmp_name']), 'attachment');
                    $response->end('ignored');
                } elseif ($request->server['request_uri'] === '/form') {
                    Assert::same($request->post, ['name' => 'a b', 'number' => '0']);
                    $response->end('form');
                } else {
                    $response->end(hash('sha256', $request->getContent()));
                }
            });
            Coroutine::create(fn () => $server->start());
            $client = new Client('127.0.0.1', $server->port, $ssl);
            $client->set(['timeout' => 5]);
            foreach (['', '0', "raw\0body\xff", str_repeat('x', 32768)] as $body) {
                Assert::true($client->post('/raw', $body));
                Assert::same($client->body, hash('sha256', $body));
            }
            Assert::true($client->post('/form', ['name' => 'a b', 'number' => '0']));
            Assert::same($client->body, 'form');
            $client->setData(['name' => 'example']);
            Assert::true($client->addFile($filename, 'disk', 'application/octet-stream', 'disk.bin'));
            Assert::true($client->addData("memory\0content", 'memory', 'application/octet-stream', 'memory.bin'));
            Assert::true($client->execute('/multipart'));
            Assert::same($client->body, 'multipart');
            $client->setData('this raw body must not be included');
            Assert::true($client->addData('attachment', 'memory'));
            Assert::true($client->execute('/ignored'));
            Assert::same($client->body, 'ignored');
            Assert::true($client->post('/raw-again', 'after-multipart'));
            Assert::same($client->body, hash('sha256', 'after-multipart'));
            $client->close();
            $server->shutdown();
        }
    });
} finally {
    unlink($filename);
}
echo "DONE\n";
?>
--EXPECT--
DONE
