--TEST--
swoole_http_client_coro: illegal another coroutine
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
    go(function () use ($cli) {
        co::sleep(0.001);
        $cli->close();
    });
    go(function () use ($cli) {
        $cli->get('/');
    });
    register_shutdown_function(function () use ($pm) {
        $pm->kill();
    });
    swoole_event_wait();
};
$pm->childFunc = function () use ($pm) {
    $serv = new swoole_http_server('127.0.0.1', $pm->getFreePort(), mt_rand(0, 1) ? SWOOLE_BASE : SWOOLE_PROCESS);
    $serv->set(['log_file' => '/dev/null']);
    $serv->on('workerStart', function () use ($pm, $serv) {
        $pm->wakeup();
    });
    $serv->on('request', function (swoole_http_request $request, swoole_http_response $response) use ($pm) {
        co::sleep(1);
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Fatal error: Swoole\Coroutine\Http\Client::close(): socket has already been bound to another coroutine 2. in %s on line %d