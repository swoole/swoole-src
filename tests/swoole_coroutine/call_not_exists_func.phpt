--TEST--
swoole_coroutine: call_not_exists_func
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    go(function () use ($pm) {
        Assert::throws(function () use ($pm) {
            httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
        }, Exception::class);
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(['worker_num' => 1]);
    $http->on('workerStart', function () use ($pm) {
        none();
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
Fatal error: Uncaught Error: Call to undefined function none() in %s:%d
Stack trace:
#0 {main}
  thrown in %s on line %d
[%s]	ERROR	php_swoole_server_rshutdown() (ERRNO %d): Fatal error: Uncaught Error: Call to undefined function none() in %s:%d
Stack trace:
#0 {main}
  thrown in %s on line %d
