--TEST--
swoole_http_server: iouring setting test
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->initRandomData(1);
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $headers = httpGetHeaders("http://127.0.0.1:{$pm->getFreePort()}");
    });

    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'iouring_flag' => SWOOLE_IOURING_SQPOLL,
        'iouring_entries' => 4096,
        'iouring_workers' => 16
    ]);
    $http->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
         $response->status(200, "status");
         $response->end("Hello World");
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
DONE
