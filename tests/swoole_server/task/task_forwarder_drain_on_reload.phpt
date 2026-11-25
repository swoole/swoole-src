--TEST--
swoole_server/task: a replacement worker drains queued forwards before exiting during another reload (#6139)
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

const TASK_COUNT = 128;
$generation = new Swoole\Atomic;
$currentPid = new Swoole\Atomic;
$oldPid = new Swoole\Atomic;
$forwarderPid = new Swoole\Atomic;
$blocked = new Swoole\Atomic;
$startedTasks = new Swoole\Atomic;
$releaseTasks = new Swoole\Atomic;
$unblockWorker = new Swoole\Atomic;
$finished = new Swoole\Atomic;
$forwarderStopping = new Swoole\Atomic;
$forwarderStopped = new Swoole\Atomic;
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm, $generation, $currentPid, $oldPid, $forwarderPid, $blocked, $startedTasks, $releaseTasks, $unblockWorker, $finished, $forwarderStopping, $forwarderStopped) {
    $connect = function () use ($pm) {
        $client = new Swoole\Client(SWOOLE_SOCK_TCP);
        $client->set(['open_eof_check' => true, 'package_eof' => "\n"]);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
        return $client;
    };
    $client = $connect();
    $client->send("batch\n");
    $pid = (int) trim($client->recv());
    $deadline = microtime(true) + 5;
    while ($startedTasks->get() < TASK_COUNT && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same($startedTasks->get(), TASK_COUNT);
    Assert::true(Swoole\Process::kill($pid, SIGTERM));
    $deadline = microtime(true) + 5;
    while ((!$blocked->get() || $generation->get() < 2) && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same($blocked->get(), 1);
    Assert::same($generation->get(), 2);
    $bridgePid = $currentPid->get();
    $forwarderPid->set($bridgePid);
    $releaseTasks->set(1);
    $deadline = microtime(true) + 5;
    while ($finished->get() < TASK_COUNT && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same($finished->get(), TASK_COUNT);
    // The probe enters the same ordinary pipe after every FINISH. Once it is
    // answered, the bridge owns all replies that did not fit the blocked receiver.
    $probe = $connect();
    $probe->send("ping\n");
    Assert::same((int) trim($probe->recv()), $bridgePid);
    $probe->close();
    Assert::true(Swoole\Process::kill($bridgePid, SIGTERM));
    $deadline = microtime(true) + 5;
    while (($generation->get() < 3 || (!$forwarderStopping->get() && !$forwarderStopped->get())) && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same($generation->get(), 3);
    Assert::same($forwarderStopping->get(), 1);
    Assert::same($forwarderStopped->get(), 0);
    $probe = $connect();
    $probe->send("ping\n");
    Assert::same((int) trim($probe->recv()), $currentPid->get());
    Assert::notSame($currentPid->get(), $bridgePid);
    $probe->close();
    $unblockWorker->set(1);
    Assert::same(trim($client->recv()), "OK:$pid");
    $deadline = microtime(true) + 5;
    while (!$forwarderStopped->get() && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same($forwarderStopped->get(), 1);
    $client->close();
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $generation, $currentPid, $oldPid, $forwarderPid, $blocked, $startedTasks, $releaseTasks, $unblockWorker, $finished, $forwarderStopping, $forwarderStopped) {
    Swoole\Runtime::setHookFlags(0);
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1, 'task_worker_num' => 2,
        'enable_coroutine' => true, 'task_enable_coroutine' => true,
        'reload_async' => true, 'max_wait_time' => 10, 'log_file' => '/dev/null',
        'open_eof_check' => true, 'package_eof' => "\n",
    ]);
    $server->on('workerStart', function ($server, $id) use ($pm, $generation, $currentPid) {
        if ($id === 0) {
            $currentPid->set(getmypid());
            if ($generation->add(1) === 1) {
                $pm->wakeup();
            }
        }
    });
    $server->on('workerExit', function () use ($oldPid, $forwarderPid, $blocked, $unblockWorker, $forwarderStopping) {
        if (getmypid() === $oldPid->get()) {
            $blocked->set(1);
            $deadline = microtime(true) + 5;
            while (!$unblockWorker->get() && microtime(true) < $deadline) {
                usleep(1000);
            }
        } elseif (getmypid() === $forwarderPid->get()) {
            $forwarderStopping->set(1);
        }
    });
    $server->on('workerStop', function () use ($forwarderPid, $forwarderStopped) {
        if (getmypid() === $forwarderPid->get()) {
            $forwarderStopped->set(1);
        }
    });
    $server->on('receive', function ($server, $fd, $rid, $data) use ($oldPid) {
        if (trim($data) === 'ping') {
            $server->send($fd, getmypid() . "\n");
            return;
        }
        $oldPid->set(getmypid());
        $server->send($fd, getmypid() . "\n");
        $result = $server->taskCo(range(0, TASK_COUNT - 1), 8);
        Assert::count($result, TASK_COUNT);
        foreach ($result as $index => $value) {
            Assert::same($value, str_repeat('x', 1024) . $index);
        }
        $server->send($fd, 'OK:' . getmypid() . "\n");
    });
    $server->on('task', function ($server, Swoole\Server\Task $task) use ($startedTasks, $releaseTasks, $finished) {
        $startedTasks->add();
        while (!$releaseTasks->get()) {
            Co::sleep(0.001);
        }
        Assert::true($task->finish(str_repeat('x', 1024) . $task->data));
        $finished->add();
    });
    $server->on('finish', function () {});
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
