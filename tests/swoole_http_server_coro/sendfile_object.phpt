--TEST--
swoole_http_server_coro: SendFile ranges and cleanup on the platform temporary directory
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;
use Swoole\SendFile;

use function Swoole\Coroutine\run;

$path    = tempnam(sys_get_temp_dir(), 'swoole-sendfile-coro-');
$parameterPath = tempnam(sys_get_temp_dir(), 'swoole-sendfile-coro-parameter-');
$content = str_repeat('0123456789abcdef', 8192);
file_put_contents($path, $content);
file_put_contents($parameterPath, $content);

run(function () use ($path, $parameterPath, $content) {
    $server = new Server('127.0.0.1', 0);
    $server->handle('/', function ($request, $response) use ($path, $parameterPath) {
        if ($request->server['request_uri'] === '/delete-parameter') {
            Assert::true($response->sendfile(filename: $parameterPath, delete_file: true));
            return;
        }
        $file = new SendFile($path);
        if ($request->server['request_uri'] === '/range') {
            $file->offset = 7;
            $file->length = 65537;
        } else {
            $file->deleteAfterSend = true;
        }
        Assert::true($response->sendfile($file));
    });
    Coroutine::create(function () use ($server, $path, $parameterPath, $content) {
        $client = new Client('127.0.0.1', $server->port);
        $client->set(['timeout' => 5]);
        try {
            Assert::true($client->get('/range'));
            Assert::same($client->body, substr($content, 7, 65537));
            Assert::true(is_file($path));
            Assert::true($client->get('/delete-parameter'));
            Assert::same($client->body, $content);
            Assert::true($client->get('/delete'));
            Assert::same($client->body, $content);
            // The coroutine send is complete before returning from sendfile().
            foreach ([$path, $parameterPath] as $currentPath) {
                $deadline = microtime(true) + 5;
                do {
                    clearstatcache(true, $currentPath);
                    if (!is_file($currentPath)) {
                        break;
                    }
                    Coroutine::sleep(0.001);
                } while (microtime(true) < $deadline);
                Assert::false(is_file($currentPath));
            }
        } finally {
            $client->close();
            $server->shutdown();
        }
    });
    $server->start();
});
echo "DONE\n";
?>
--EXPECT--
DONE
