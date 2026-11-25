--TEST--
swoole_server/task: forwarding task results stays nonblocking while the old worker cannot read (#6139)
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
$oldPid = new Swoole\Atomic;
$blocked = new Swoole\Atomic;
$releaseTasks = new Swoole\Atomic;
$unblockWorker = new Swoole\Atomic;
$finished = new Swoole\Atomic;
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm, $generation, $oldPid, $blocked, $releaseTasks, $unblockWorker, $finished) {
    $connect = function () use ($pm) {
        $client = new Swoole\Client(SWOOLE_SOCK_TCP);
        $client->set(['open_eof_check' => true, 'package_eof' => "\n"]);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
        return $client;
    };
    $client = $connect();
    $client->send("batch\n");
    $pid = (int) trim($client->recv());
    Assert::true(Swoole\Process::kill($pid, SIGTERM));
    $deadline = microtime(true) + 5;
    while ((!$blocked->get() || $generation->get() < 2) && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same($blocked->get(), 1);
    Assert::same($generation->get(), 2);
    $releaseTasks->set(1);
    $deadline = microtime(true) + 5;
    while ($finished->get() < TASK_COUNT && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same($finished->get(), TASK_COUNT);
    // FINISH traffic fills the old worker's datagram receive queue. Its replacement
    // must still answer a new request instead of blocking in sendto()/send().
    $probe = $connect();
    $probe->send("ping\n");
    Assert::notSame((int) trim($probe->recv()), $pid);
    $probe->close();
    $unblockWorker->set(1);
    Assert::same(trim($client->recv()), "OK:$pid");
    $client->close();
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $generation, $oldPid, $blocked, $releaseTasks, $unblockWorker, $finished) {
    Swoole\Runtime::setHookFlags(0);
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1, 'task_worker_num' => 2,
        'enable_coroutine' => true, 'task_enable_coroutine' => true,
        'reload_async' => true, 'max_wait_time' => 10, 'log_file' => '/dev/null',
        'open_eof_check' => true, 'package_eof' => "\n",
    ]);
    $server->on('workerStart', function ($server, $id) use ($pm, $generation) {
        if ($id === 0 && $generation->add(1) === 1) {
            $pm->wakeup();
        }
    });
    $server->on('workerExit', function () use ($oldPid, $blocked, $unblockWorker) {
        if (getmypid() === $oldPid->get()) {
            $blocked->set(1);
            $deadline = microtime(true) + 5;
            while (!$unblockWorker->get() && microtime(true) < $deadline) {
                usleep(1000);
            }
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
    $server->on('task', function ($server, Swoole\Server\Task $task) use ($releaseTasks, $finished) {
        while (!$releaseTasks->get()) {
            Co::sleep(0.001);
        }
        Assert::true($task->finish(str_repeat('x', 1024) . $task->data));
        Assert::true($task->finish('duplicate:' . $task->data));
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
