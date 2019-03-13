--TEST--
swoole_http_server: enable_coroutine setting in server
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_function_not_exist('curl_init');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Request;
use Swoole\Http\Response;

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    echo curlGet("http://127.0.0.1:{$pm->getFreePort()}/") . "\n";
    echo curlGet("http://127.0.0.1:{$pm->getFreePort()}/co") . "\n";
    echo curlGet("http://127.0.0.1:{$pm->getFreePort()}/co") . "\n";
    echo curlGet("http://127.0.0.1:{$pm->getFreePort()}/co") . "\n";
    swoole_process::kill($pid);
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort());
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