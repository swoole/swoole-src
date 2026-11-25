--TEST--
swoole_server/task: forward results to their original coroutine across consecutive worker replacements (#6139)
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$generation = new Swoole\Atomic;
$fastFinished = [new Swoole\Atomic, new Swoole\Atomic, new Swoole\Atomic];
$release = [new Swoole\Atomic, new Swoole\Atomic, new Swoole\Atomic];
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm, $generation, $fastFinished, $release) {
    $clients = [];
    $pids = [];
    for ($i = 0; $i < 3; $i++) {
        $client = new Swoole\Client(SWOOLE_SOCK_TCP);
        $client->set(['open_eof_check' => true, 'package_eof' => "\n"]);
        Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
        $client->send("batch:$i\n");
        $pids[] = (int) trim($client->recv());
        $clients[] = $client;
        $deadline = microtime(true) + 5;
        while (!$fastFinished[$i]->get() && microtime(true) < $deadline) {
            usleep(1000);
        }
        Assert::same($fastFinished[$i]->get(), 1);
        // The fast FINISH was sent before this request enters the same ordinary pipe.
        $probe = new Swoole\Client(SWOOLE_SOCK_TCP);
        $probe->set(['open_eof_check' => true, 'package_eof' => "\n"]);
        Assert::true($probe->connect('127.0.0.1', $pm->getFreePort(), 5));
        $probe->send("ping\n");
        Assert::same(trim($probe->recv()), (string) $pids[$i]);
        $probe->close();
        if ($i < 2) {
            Assert::true(Swoole\Process::kill($pids[$i], SIGTERM));
            $deadline = microtime(true) + 5;
            while ($generation->get() < $i + 2 && microtime(true) < $deadline) {
                usleep(1000);
            }
            Assert::same($generation->get(), $i + 2);
        }
    }
    Assert::count(array_unique($pids), 3);
    // All three generations still own a partially completed result collection.
    foreach ($release as $gate) {
        $gate->set(1);
    }
    foreach ($clients as $i => $client) {
        $result = json_decode(trim($client->recv()), true);
        Assert::same($result, ['pid' => $pids[$i], 'results' => [
            'fast' => 'fast', 'small' => 'small', 'large' => str_repeat('L', 16384),
        ]]);
        $client->close();
    }
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $generation, $fastFinished, $release) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1, 'task_worker_num' => 2,
        'enable_coroutine' => true, 'task_enable_coroutine' => true,
        'task_use_object' => true, 'reload_async' => true, 'max_wait_time' => 10,
        'open_eof_check' => true, 'package_eof' => "\n", 'log_file' => '/dev/null',
    ]);
    $server->on('workerStart', function ($server, $id) use ($pm, $generation) {
        if ($id === 0 && $generation->add(1) === 1) {
            $pm->wakeup();
        }
    });
    $server->on('receive', function ($server, $fd, $rid, $data) {
        if (trim($data) === 'ping') {
            $server->send($fd, getmypid() . "\n");
            return;
        }
        $index = (int) substr(trim($data), 6);
        $server->send($fd, getmypid() . "\n");
        $results = $server->taskCo([
            'fast' => [$index, 'fast'], 'small' => [$index, 'small'], 'large' => [$index, 'large'],
        ], 8);
        $server->send($fd, json_encode(['pid' => getmypid(), 'results' => $results]) . "\n");
    });
    $server->on('task', function ($server, Swoole\Server\Task $task) use ($fastFinished, $release) {
        [$index, $kind] = $task->data;
        if ($kind === 'fast') {
            Assert::true($task->finish('fast'));
            $fastFinished[$index]->set(1);
            return;
        }
        while (!$release[$index]->get()) {
            Co::sleep(0.001);
        }
        Assert::true($task->finish($kind === 'large' ? str_repeat('L', 16384) : 'small'));
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
