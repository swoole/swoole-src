--TEST--
swoole_server: shutdown in master process
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $pm = new SwooleTest\ProcessManager;
    $pm->initRandomData(1);

    $pm->parentFunc = function () use ($pm) {

    };

    $pm->childFunc = function () use ($pm, $mode) {
        $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set([
            'worker_num' => 4,
            'log_file' => '/dev/null',
        ]);
        $server->on('start', function (Swoole\Server $server) use ($pm, $mode) {
            echo "START [$mode]\n";
            $pm->wakeup();
            $server->shutdown();
        });
        $server->on('receive', function () { });
        $server->on('shutdown', function () {
            echo "SHUTDOWN\n";
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->setExpectExitSignal(0);
    $pm->run();
    $pm->expectExitCode(0);
}
?>
--EXPECTF--
START [%d]
SHUTDOWN
START [%d]
SHUTDOWN
