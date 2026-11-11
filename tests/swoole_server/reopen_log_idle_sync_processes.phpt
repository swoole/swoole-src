--TEST--
swoole_server: idle manager and synchronous task workers reopen logs without receiving a task
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
skip_if_function_not_exist('posix_kill');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

foreach ([1, 2, 3, 4] as $ipc) {
    foreach (['manager', 'task'] as $target) {
        $log = tempnam(sys_get_temp_dir(), 'swoole-log-signal-');
        $rotated = $log . '.old';
        $ready = new Swoole\Atomic();
        $managerPid = new Swoole\Atomic();
        $taskPid = new Swoole\Atomic();
        $pm = new ProcessManager();
        $pm->parentFunc = function () use ($pm, $log, $rotated, $target, $managerPid, $taskPid) {
            try {
                Assert::true(rename($log, $rotated));
                $pid = ($target === 'manager' ? $managerPid : $taskPid)->get();
                Assert::greaterThan($pid, 0);
                Assert::true(posix_kill($pid, SIGWINCH));
                $deadline = microtime(true) + 5;
                do {
                    clearstatcache(true, $log);
                    if (is_file($log)) {
                        break;
                    }
                    usleep(1000);
                } while (microtime(true) < $deadline);
                Assert::true(is_file($log));
            } finally {
                $pm->kill();
                @unlink($log);
                @unlink($rotated);
            }
        };
        $pm->childFunc = function () use ($pm, $log, $ipc, $ready, $managerPid, $taskPid) {
            $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
            $server->set([
                'worker_num' => 1,
                'reactor_num' => 1,
                'task_worker_num' => 1,
                'task_ipc_mode' => $ipc,
                'task_enable_coroutine' => false,
                'enable_coroutine' => false,
                'log_file' => $log,
            ]);
            $server->on('ManagerStart', function () use ($pm, $ready, $managerPid) {
                $managerPid->set(getmypid());
                if ($ready->add() === 3) {
                    $pm->wakeup();
                }
            });
            $server->on('WorkerStart', function ($server, $id) use ($pm, $ready, $taskPid) {
                if ($server->taskworker) {
                    $taskPid->set(getmypid());
                }
                if ($ready->add() === 3) {
                    $pm->wakeup();
                }
            });
            $server->on('Receive', function () {});
            $server->on('Task', function () {});
            $server->on('Finish', function () {});
            $server->start();
        };
        $pm->childFirst();
        $pm->run();
    }
}
echo "DONE\n";
?>
--EXPECT--
DONE
