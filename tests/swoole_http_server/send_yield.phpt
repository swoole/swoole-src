--TEST--
swoole_http_server: send yield
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->initRandomData(1, 64 * 1024 * 1024);
$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $data = httpCoroGet("http://127.0.0.1:{$pm->getFreePort()}/");
        assert($data === $pm->getRandomData());
        phpt_var_dump(strlen($data));
        $pm->kill();
        echo "DONE\n";
    });
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $http->set(['send_yield' => true]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
        $response->write($pm->getRandomData());
        $response->end();
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
