--TEST--
swoole_server/task: forwarding socket timers are cancelled on send failure and graceful exit (#6139)
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_win();
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

foreach ([false, true] as $lateResult) {
    $generation = new Swoole\Atomic;
    $started = new Swoole\Atomic;
    $release = new Swoole\Atomic;
    $releaseLate = new Swoole\Atomic;
    $lateSent = new Swoole\Atomic;
    $oldPid = new Swoole\Atomic;
    $stopped = new Swoole\Atomic;
    $logFile = sys_get_temp_dir() . '/swoole-6139-expiry-' . getmypid() . '-' . (int) $lateResult . '.log';
    $pm = new SwooleTest\ProcessManager;
    $pm->parentFunc = function () use ($pm, $generation, $started, $release, $releaseLate, $lateSent, $oldPid, $stopped, $lateResult) {
        $client = new Swoole\Client(SWOOLE_SOCK_TCP);
        $client->set(['open_eof_check' => true, 'package_eof' => "\n"]);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
        $client->send("run\n");
        $pid = (int) trim($client->recv());
        $oldPid->set($pid);
        $deadline = microtime(true) + 5;
        while (!$started->get() && microtime(true) < $deadline) {
            usleep(1000);
        }
        Assert::same($started->get(), 1);
        Assert::true(Swoole\Process::kill($pid, SIGTERM));
        $deadline = microtime(true) + 5;
        while ($generation->get() < 2 && microtime(true) < $deadline) {
            usleep(1000);
        }
        Assert::same($generation->get(), 2);
        $release->set(1);
        Assert::same(trim($client->recv()), 'OK');
        $deadline = microtime(true) + 5;
        while (!$stopped->get() && microtime(true) < $deadline) {
            usleep(1000);
        }
        Assert::same($stopped->get(), 1);
        if ($lateResult) {
            // The cached connected sender now points at a closed receiver.
            $releaseLate->set(1);
            $deadline = microtime(true) + 5;
            while (!$lateSent->get() && microtime(true) < $deadline) {
                usleep(1000);
            }
            Assert::same($lateSent->get(), 1);
            $probe = new Swoole\Client(SWOOLE_SOCK_TCP);
            Assert::true($probe->connect('127.0.0.1', $pm->getFreePort(), 5));
            $probe->send("ping\n");
            Assert::same((int) trim($probe->recv()), 0);
            $probe->close();
        }
        $client->close();
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $generation, $started, $release, $releaseLate, $lateSent, $oldPid, $stopped, $lateResult, $logFile) {
        $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
        $server->set([
            'worker_num' => 1, 'task_worker_num' => 1, 'enable_coroutine' => true,
            'reload_async' => true, 'max_wait_time' => 2, 'log_file' => $logFile,
            'log_level' => SWOOLE_LOG_WARNING,
            'open_eof_check' => true, 'package_eof' => "\n",
        ]);
        $server->on('workerStart', function ($server, $id) use ($pm, $generation) {
            if ($id === 0 && $generation->add(1) === 1) {
                $pm->wakeup();
            }
        });
        $server->on('workerStop', function () use ($oldPid, $stopped) {
            if (getmypid() === $oldPid->get()) {
                $stopped->set(1);
            }
        });
        $server->on('receive', function ($server, $fd, $rid, $data) {
            if (trim($data) === 'ping') {
                $server->send($fd, Swoole\Timer::stats()['num'] . "\n");
                return;
            }
            $server->send($fd, getmypid() . "\n");
            Assert::integer($server->task('work', -1, function ($server) use ($fd) {
                $server->send($fd, "OK\n");
            }));
        });
        $server->on('task', function ($server, $id, $source, $data) use ($started, $release, $releaseLate, $lateSent, $lateResult) {
            $started->set(1);
            $deadline = microtime(true) + 5;
            while (!$release->get() && microtime(true) < $deadline) {
                usleep(1000);
            }
            Assert::true($server->finish('done'));
            if ($lateResult) {
                $deadline = microtime(true) + 5;
                while (!$releaseLate->get() && microtime(true) < $deadline) {
                    usleep(1000);
                }
                Assert::true($server->finish('late'));
                $lateSent->set(1);
            }
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
    Assert::false(str_contains(file_get_contents($logFile), 'worker exit timeout'));
    unlink($logFile);
}
echo "DONE\n";
?>
--EXPECT--
DONE
