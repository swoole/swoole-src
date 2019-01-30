--TEST--
swoole_coroutine: throw exception in server on request
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->set(['timeout' => 5]);
        assert($cli->get('/'));
        assert($cli->statusCode === 500);
        $pm->kill();
    });
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
Warning: [Coroutine#2] Uncaught Exception: whoops in %s/swoole_coroutine/exception/exception.php:21
Stack trace:
#0 {main}
  thrown in %s/swoole_coroutine/exception/exception.php on line 21
