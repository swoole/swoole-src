--TEST--
swoole_http_server: max coro num
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->initRandomData(2);
$pm->parentFunc = function ($pid) use ($pm) {
    switch_process();
    go(function () use ($pm) {
        $statusCode = httpGetStatusCode("http://127.0.0.1:{$pm->getFreePort()}", ['timeout' => 0.1]);
        echo PHP_EOL . $statusCode . PHP_EOL;
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    Co::set(['max_coroutine' => 1]);
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $http->set(['log_file' => '/dev/null']);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
        Co::yield();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
        echo "never here\n";
        $response->end($pm->getRandomData());
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Warning: Swoole\Server::start(): exceed max number of coroutine 1 in %s on line %d

Warning: Swoole\Server::start(): Swoole\Http\Server->onRequest handler error in %s on line %d

503
