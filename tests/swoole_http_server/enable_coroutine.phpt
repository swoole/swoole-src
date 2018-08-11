--TEST--
swoole_http_server: enable_coroutine setting in server
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/../include/lib/curl.php';

use Swoole\Http\Request;
use Swoole\Http\Response;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) {
    echo curlGet('http://127.0.0.1:9501/') . "\n";
    echo curlGet('http://127.0.0.1:9501/co') . "\n";
    echo curlGet('http://127.0.0.1:9501/co') . "\n";
    echo curlGet('http://127.0.0.1:9501/co') . "\n";
    swoole_process::kill($pid);
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', 9501);
    $http->set([
        'enable_coroutine' => false, // close build-in coroutine
        'worker_num' => 1,
        'log_level' => -1
    ]);
    $http->on("request", function (Request $request, Response $response) {
        $response->header("Content-Type", "text/plain");
        if ($request->server['request_uri'] == '/co') {
            go(function () use ($response) {
                $response->end(Co::getuid());
            });
        } else {
            $response->end(Co::getuid());
        }
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
-1
1
2
3