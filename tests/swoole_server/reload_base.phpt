--TEST--
swoole_server: unregistered signal
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$counter = [
    'worker' => new Swoole\Atomic(),
    'task_worker' => new Swoole\Atomic()
];
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    global $counter;
    while (!file_exists(TEST_PID_FILE)) {
        usleep(100 * 1000);
    }
    $pid = file_get_contents(TEST_PID_FILE);
    $random = mt_rand(1, 10);
    usleep(100 * 1000);
    for ($n = $random; $n--;) {
        Swoole\Process::kill($pid, SIGUSR1);
        usleep(100 * 1000);
        Swoole\Process::kill($pid, SIGUSR2);
        usleep(100 * 1000);
    }

    /**@var $counter Swoole\Atomic[] */
    foreach ($counter as $key => $atomic) {
        $count = $atomic->get();
        assert($atomic->get() === $random, "[{$key} reload {$count} but expect {$random}]");
    }
    $log = file_get_contents(TEST_LOG_FILE);
    $log = trim(preg_replace('/.+?\s+?NOTICE\s+?.+/', '', $log));
    assert(empty($log));
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    @unlink(TEST_LOG_FILE);
    @unlink(TEST_PID_FILE);
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'log_file' => TEST_LOG_FILE,
        'pid_file' => TEST_PID_FILE,
        'task_worker_num' => 1
    ]);
    $server->on('Start', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('WorkerStart', function (Swoole\Server $server, int $worker_id) use ($pm) {
        if ($server->started[$worker_id] ?? false) {
            $server->started[$worker_id] = true;
        } else {
            /**@var $counter Swoole\Atomic[] */
            global $counter;
            $atomic = $server->taskworker ? $counter['task_worker'] : $counter['worker'];
            $atomic->add(1);
        }
    });
    $server->on('Receive', function (Swoole\Server $server, $fd, $reactor_id, $data) { });
    $server->on('Task', function () { });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
