
--TEST--
swoole_http_server: release the content type when Content-Encoding disables compression
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Client;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Http\Server;

const N = 500;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Client('127.0.0.1', $pm->getFreePort());
        $client->setHeaders(['Accept-Encoding' => 'gzip']);
        Assert::true($client->get('/memory'));
        $before = (int) $client->getBody();
        for ($i = 0; $i < N; $i++) {
            Assert::true($client->get('/'));
            Assert::same($client->getHeaders()['content-encoding'], 'gzip');
            Assert::same($client->getBody(), 'hello');
        }
        Assert::true($client->get('/memory'));
        // each leaked content type holds more than 1 KiB
        Assert::lessThan((int) $client->getBody() - $before, N * 256);
    });
    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'http_compression_types' => ['text/html'],
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Request $request, Response $response) {
        if ($request->server['request_uri'] === '/memory') {
            $response->end((string) memory_get_usage());
            return;
        }
        // a runtime string is refcounted, unlike an interned literal
        $response->header('Content-Type', 'text/html; x=' . str_repeat('a', 1024));
        $response->header('Content-Encoding', 'gzip');
        $response->end(gzencode('hello'));
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
