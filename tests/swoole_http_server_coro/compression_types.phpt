--TEST--
swoole_http_server_coro: compression types
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_test_cases.php';

use Swoole\Coroutine\Http\Server;
use Swoole\Http\Response;
use Swoole\Http\Request;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    http_compression_types_test($pm);
    echo "DONE\n";
    file_get_contents('http://127.0.0.1:' . $pm->getFreePort() . '/shutdown');
};
$pm->childFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $server = new Server("127.0.0.1", $pm->getFreePort(), false);
        $server->set([
            'http_compression_types' => [
                'text/html',
                'application/json'
            ],
        ]);
        $server->handle('/', function (Request $request, Response $response) {
            if ($request->server['request_uri'] == '/html') {
                $response->end(str_repeat('A', $request->get['bytes']));
            } elseif ($request->server['request_uri'] == '/json') {
                $response->setHeader('Content-Type', 'application/json');
                $response->end(str_repeat('B', $request->get['bytes']));
            } elseif ($request->server['request_uri'] == '/raw') {
                $response->setHeader('Content-Type', 'text/raw');
                $response->end(str_repeat('C', $request->get['bytes']));
            }
        });
        $server->handle('/shutdown', function ($request, $response) use ($server) {
            $response->end("shutdown");
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
