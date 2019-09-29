--TEST--
swoole_server: reload in base mode
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
trigger_error('SWOOLE_BASE not support reload task workers.', E_USER_NOTICE);
$worker_num = swoole_cpu_num() * 2;
$counter = [
    'worker' => new Swoole\Atomic(),
    'task_worker' => new Swoole\Atomic()
];
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    global $counter, $worker_num;
    while (!file_exists(TEST_PID_FILE)) {
        usleep(100 * 1000);
    }
    $pid = file_get_contents(TEST_PID_FILE);
    $random = mt_rand(1, 12);
    usleep(100 * 1000);
    for ($n = $random; $n--;) {
        Swoole\Process::kill($pid, SIGUSR1);
        usleep(100 * 1000);
        // Swoole\Process::kill($pid, SIGUSR2);
        // usleep(100 * 1000);
    }

    /**@var $counter Swoole\Atomic[] */
    $total = $counter['worker']->get() - $worker_num;
    $expect = $random * $worker_num;
    Assert::same($total, $expect, "[worker reload {$total} but expect {$expect}]");

    // $total = $counter['task_worker']->get() - 1;
    // Assert::same($total, $random * 2, "[task worker reload {$total} but expect {$random}]");

    $log = file_get_contents(TEST_LOG_FILE);
    $log = trim(preg_replace('/.+?\s+?INFO\s+?.+/', '', $log));
    if (!Assert::assert(empty($log))){
        var_dump($log);
    }
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    global $worker_num;
    @unlink(TEST_LOG_FILE);
    @unlink(TEST_PID_FILE);
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'log_file' => TEST_LOG_FILE,
        'pid_file' => TEST_PID_FILE,
        'worker_num' => $worker_num
        // 'task_worker_num' => 1
    ]);
    $server->on('ManagerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('WorkerStart', function (Swoole\Server $server, int $worker_id) use ($pm) {
        /**@var $counter Swoole\Atomic[] */
        global $counter;
        $atomic = $server->taskworker ? $counter['task_worker'] : $counter['worker'];
        $atomic->add(1);
    });
    $server->on('Receive', function (Swoole\Server $server, $fd, $reactor_id, $data) { });
    // $server->on('Task', function () { });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Notice: SWOOLE_BASE not support reload task workers. in %s on line %d
DONE
