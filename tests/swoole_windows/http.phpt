--TEST--
swoole_windows: coroutine http server
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (stripos(PHP_OS, 'WIN') !== 0) {
    die('skip Windows only');
}
if (!class_exists(Swoole\Coroutine\Http\Server::class, false)) {
    die('skip coroutine http server not available');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Server;
use function Swoole\Coroutine\run;

Co::set(['hook_flags' => 0]);

$pm = new SwooleTest\ProcessManager();
$pm->parentFunc = function () use ($pm) {
    $port = $pm->getFreePort();

    $fetch = function (string $path) use ($port): string {
        $url = "http://127.0.0.1:{$port}{$path}";
        for ($i = 0; $i < 50; $i++) {
            $body = @file_get_contents($url);
            if ($body !== false) {
                return $body;
            }
            usleep(100000);
        }
        throw new RuntimeException("failed to fetch {$path}");
    };

    Assert::same($fetch('/'), "<h1>Index</h1>");
    Assert::same($fetch('/test'), "<h1>Test</h1>");
    Assert::same($fetch('/stop'), "<h1>Stop</h1>");

    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $port = $pm->getFreePort();

    run(function () use ($pm, $port) {
        $server = new Server('127.0.0.1', $port, false);
        $server->handle('/', function ($request, $response) {
            $response->end("<h1>Index</h1>");
        });
        $server->handle('/test', function ($request, $response) {
            $response->end("<h1>Test</h1>");
        });
        $server->handle('/stop', function ($request, $response) use ($server) {
            $response->end("<h1>Stop</h1>");
            $server->shutdown();
        });

        $pm->wakeup();
        $server->start();
    });
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
