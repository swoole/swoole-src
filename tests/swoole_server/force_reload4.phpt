--TEST--
swoole_server: force reload (timer)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Timer;

$pm = new SwooleTest\ProcessManager;
$pm->setWaitTimeout(30);
$pm->parentFunc = function () use ($pm) {
    echo "OK\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort());
    $server->set([
        'reload_async' => true,
        'task_enable_coroutine' => true,
        'max_wait_time' => 2,
    ]);
    $server->on("shutdown", function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('workerStart', function (Swoole\Server $server, int $wid) use ($pm) {
        if ($wid === 0) {
            Timer::tick(5000, function () {
                echo 'tick';
            });
            Timer::after(500, function () use ($server) {
                $server->shutdown();
            });
        }
    });
    $server->on('receive', function () { });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
[%s]	INFO	Server is shutdown now
[%s]	WARNING	%s (ERRNO 9101): worker exit timeout, forced termination
OK
