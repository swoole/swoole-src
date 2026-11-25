--TEST--
swoole_server/task: an existing request can submit taskwait and taskWaitMulti after its worker starts draining (#6139)
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$generation = new Swoole\Atomic;
$release = new Swoole\Atomic;
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm, $generation, $release) {
    $client = new Swoole\Client(SWOOLE_SOCK_TCP);
    $client->set(['open_eof_check' => true, 'package_eof' => "\n"]);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
    $client->send("run\n");
    $pid = (int) trim($client->recv());
    Assert::true(Swoole\Process::kill($pid, SIGTERM));
    $deadline = microtime(true) + 5;
    while ($generation->get() < 2 && microtime(true) < $deadline) {
        usleep(1000);
    }
    Assert::same($generation->get(), 2);
    $release->set(1);
    Assert::same(json_decode(trim($client->recv()), true), [
        'pid' => $pid, 'single' => 'single', 'batch' => ['small' => 'small', 'large' => str_repeat('B', 16384)],
    ]);
    $client->close();
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $generation, $release) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1, 'task_worker_num' => 2, 'enable_coroutine' => true,
        'reload_async' => true, 'max_wait_time' => 8, 'log_file' => '/dev/null',
        'open_eof_check' => true, 'package_eof' => "\n",
    ]);
    $server->on('workerStart', function ($server, $id) use ($pm, $generation) {
        if ($id === 0 && $generation->add(1) === 1) {
            $pm->wakeup();
        }
    });
    $server->on('receive', function ($server, $fd) use ($release) {
        $pid = getmypid();
        $server->send($fd, "$pid\n");
        while (!$release->get()) {
            Co::sleep(0.001);
        }
        Assert::notSame($server->getWorkerPid(0), $pid);
        $single = $server->taskwait('single', 3);
        $batch = $server->taskWaitMulti(['small' => 'small', 'large' => str_repeat('B', 16384)], 3);
        $server->send($fd, json_encode(['pid' => getmypid(), 'single' => $single, 'batch' => $batch]) . "\n");
    });
    $server->on('task', function ($server, $id, $source, $data) { return $data; });
    $server->on('finish', function () {});
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
