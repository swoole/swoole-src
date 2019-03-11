--TEST--
swoole_coroutine: throw exception
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_function_not_exist('curl_init');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    echo curlGet("http://127.0.0.1:{$pm->getFreePort()}/");
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(['worker_num' => 1]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        co::sleep(0.001);
        throw new Exception('whoops');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Fatal error: Uncaught Exception: whoops in %s/tests/swoole_coroutine/exception.php:15
Stack trace:
#0 {main}
  thrown in %s/tests/swoole_coroutine/exception.php on line 15
