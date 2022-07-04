--TEST--
swoole_http_server: compression types
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/http_test_cases.php';

use Swoole\Http\Response;
use Swoole\Http\Request;
use Swoole\Http\Server;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    http_compression_types_test($pm);
    echo "DONE\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP);
    $http->set([
        'http_compression_types' => [
            'text/html',
            'application/json'
        ],
    ]);
    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });
    $http->on("request", function (Request $request, Response $response) {
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
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
