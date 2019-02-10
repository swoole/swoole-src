--TEST--
swoole_server: reload async
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$reloaded = new Swoole\Atomic;
$pm = new ProcessManager;
$pm->setWaitTimeout(-1);
$pm->parentFunc = function () use ($pm) {
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm, $reloaded) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $server->set([
        'log_file' => '/dev/null',
        'worker_num' => mt_rand(2, swoole_cpu_num() * 2),
        'max_wait_time' => 5,
        'reload_async' => true,
    ]);
    $server->on('WorkerStart', function (Swoole\Server $server, int $worker_id) use ($pm, $reloaded) {
        if ($worker_id === 0) {
            usleep(100 * 1000); // wait for the other processed
            if ($reloaded->get() != 1) {
                go(function () use ($pm) {
                    for ($n = 1; $n <= 5; $n++) {
                        Co::sleep(0.1);
                        echo "{$n}\n";
                    }
                    echo "RELOADED\n";
                    $pm->wakeup();
                });
                echo "RELOAD\n";
                $reloaded->set(1);
                assert($server->reload());
            }
        }
    });
    $server->on('Receive', function () { });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
RELOAD
1
2
3
4
5
RELOADED
DONE
