--TEST--
swoole_http_client_coro: multipart retries retain the original fields and file parts across configuration changes
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;

Assert::setThrowException(true);
$file = tempnam(sys_get_temp_dir(), 'swoole-multipart-retry-');
file_put_contents($file, "disk\0content");
try {
    Coroutine\run(function () use ($file) {
        foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $ssl) {
            foreach (['memory', 'disk', 'both'] as $mode) {
                $server = new Server('127.0.0.1', 0, $ssl);
                $server->set(['http_compression' => false,
                    'ssl_cert_file' => SSL_FILE_DIR . '/server.crt', 'ssl_key_file' => SSL_FILE_DIR . '/server.key']);
                $client = new Client('127.0.0.1', $server->port, $ssl);
                $client->set(['timeout' => 5, 'max_retries' => 2]);
                $client->setMethod('POST');
                $client->setData(['name' => 'original']);
                if ($mode !== 'disk') {
                    $client->addData("memory\0content", 'memory', 'application/octet-stream', 'memory.bin');
                }
                if ($mode !== 'memory') {
                    $client->addFile($file, 'disk', 'application/octet-stream', 'disk.bin');
                }
                $attempts = 0;
                $server->handle('/', function ($request, $response) use ($client, $mode, &$attempts) {
                    if ($request->server['request_uri'] === '/after') {
                        Assert::same($request->post, ['pending' => 'next']);
                        Assert::same($request->files ?? [], []);
                        $response->end('next');
                        return;
                    }
                    Assert::same($request->post, ['name' => 'original']);
                    if ($mode !== 'disk') {
                        Assert::same(file_get_contents($request->files['memory']['tmp_name']), "memory\0content");
                        Assert::same($request->files['memory']['name'], 'memory.bin');
                    }
                    if ($mode !== 'memory') {
                        Assert::same(file_get_contents($request->files['disk']['tmp_name']), "disk\0content");
                        Assert::same($request->files['disk']['name'], 'disk.bin');
                    }
                    $status = [502, 503, 200][$attempts++];
                    if ($attempts === 1) {
                        $client->setData(['pending' => 'next']);
                        $client->uploadFiles = [];
                    }
                    $response->status($status);
                    $response->header('Connection', 'close');
                    $response->end($status === 200 ? 'done' : 'retry');
                });
                Coroutine::create(fn () => $server->start());
                Assert::true($client->execute('/upload'));
                Assert::same($attempts, 3);
                Assert::same($client->body, 'done');
                Assert::same($client->requestBody, ['pending' => 'next']);
                Assert::null($client->uploadFiles);
                Assert::true($client->execute('/after'));
                Assert::same($client->body, 'next');
                $client->close();
                $server->shutdown();
            }
        }
    });
} finally {
    unlink($file);
}
echo "DONE\n";
?>
--EXPECT--
DONE
