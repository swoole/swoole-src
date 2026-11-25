--TEST--
swoole_server/task: duplicate results do not release a worker with an untimed pending task wait (#6139)
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$generation = new Swoole\Atomic;
$fastFinished = new Swoole\Atomic;
$release = new Swoole\Atomic;
$oldPid = new Swoole\Atomic;
$stopped = new Swoole\Atomic;
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm, $generation, $fastFinished, $release, $oldPid, $stopped) {
    $client = new Swoole\Client(SWOOLE_SOCK_TCP);
    $client->set(['open_eof_check' => true, 'package_eof' => "\n"]);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
    $client->send("batch\n");
    $pid = (int) trim($client->recv());
    $oldPid->set($pid);
    $deadline = microtime(true) + 5;
    while (!$fastFinished->get() && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same($fastFinished->get(), 1);
    $probe = new Swoole\Client(SWOOLE_SOCK_TCP);
    Assert::true($probe->connect('127.0.0.1', $pm->getFreePort(), 5));
    $probe->send("ping\n");
    Assert::same((int) trim($probe->recv()), $pid);
    $probe->close();
    Assert::true(Swoole\Process::kill($pid, SIGTERM));
    $deadline = microtime(true) + 5;
    while ($generation->get() < 2 && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same($generation->get(), 2);
    $release->set(1);
    Assert::same(json_decode(trim($client->recv()), true), ['fast' => 'fast', 'slow' => 'slow']);
    $deadline = microtime(true) + 5;
    while (!$stopped->get() && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same($stopped->get(), 1);
    $client->close();
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $generation, $fastFinished, $release, $oldPid, $stopped) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1, 'task_worker_num' => 1,
        'enable_coroutine' => true, 'task_enable_coroutine' => true,
        'reload_async' => true, 'max_wait_time' => 8, 'log_file' => '/dev/null',
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
            $server->send($fd, getmypid() . "\n");
            return;
        }
        $server->send($fd, getmypid() . "\n");
        $result = $server->taskCo(['fast' => 'fast', 'slow' => 'slow'], -1);
        $server->send($fd, json_encode($result) . "\n");
    });
    $server->on('task', function ($server, Swoole\Server\Task $task) use ($fastFinished, $release) {
        if ($task->data === 'fast') {
            Assert::true($task->finish('fast'));
            Assert::true($task->finish('duplicate'));
            $fastFinished->set(1);
            return;
        }
        while (!$release->get()) {
            Co::sleep(0.001);
        }
        Assert::true($task->finish('slow'));
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
