--TEST--
swoole_http_server: disable coroutine and use go
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
$pm->parentFunc = function () use ($pm) {
    for ($n = 0; $n > MAX_REQUESTS; $n++) {
        assert(curlGet("http://127.0.0.1:{$pm->getFreePort()}/") == $n);
    }
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'enable_coroutine' => false, // close build-in coroutine
    ]);
    $http->on("request", function (Request $request, Response $response) {
        go(function () use ($response) {
            co::sleep(0.001);
            $cid = go(function () use ($response) {
                co::yield();
                $response->end(Co::getuid());
            });
            co::resume($cid);
        });
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
