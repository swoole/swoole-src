--TEST--
swoole_server/task: global onFinish does not pin a draining worker and runs in its replacement (#6139)
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$generation = new Swoole\Atomic;
$started = new Swoole\Atomic;
$release = new Swoole\Atomic;
$oldPid = new Swoole\Atomic;
$stopped = new Swoole\Atomic;
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm, $generation, $started, $release, $oldPid, $stopped) {
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
    while ((!$stopped->get() || $generation->get() < 2) && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same($stopped->get(), 1);
    Assert::same($generation->get(), 2);
    $release->set(1);
    $result = json_decode(trim($client->recv()), true);
    Assert::isArray($result);
    Assert::notSame($result['pid'], $pid);
    Assert::same($result['data'], 'global');
    $client->close();
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $generation, $started, $release, $oldPid, $stopped) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1, 'task_worker_num' => 1, 'enable_coroutine' => true,
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
    $server->on('receive', function ($server, $fd) {
        $server->send($fd, getmypid() . "\n");
        Assert::integer($server->task($fd));
    });
    $server->on('task', function ($server, $id, $source, $data) use ($started, $release) {
        $started->set(1);
        $deadline = microtime(true) + 5;
        while (!$release->get() && microtime(true) < $deadline) {
            usleep(1000);
        }
        return ['fd' => $data, 'data' => 'global'];
    });
    $server->on('finish', function ($server, $id, $result) {
        $server->send($result['fd'], json_encode(['pid' => getmypid(), 'data' => $result['data']]) . "\n");
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
