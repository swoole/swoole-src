--TEST--
swoole_server: shutdown in master process
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->initRandomData(1);
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $server->set(['worker_num' => mt_rand(1, 4), 'log_file' => '/dev/null']);
    $server->on('start', function (Swoole\Server $server) use ($pm) {
        echo "START\n";
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
$pm->run();
$pm->expectExitCode(0);
?>
--EXPECT--
START
SHUTDOWN
