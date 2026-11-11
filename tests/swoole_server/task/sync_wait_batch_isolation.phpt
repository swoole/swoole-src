--TEST--
swoole_server/task: timed-out synchronous results cannot overwrite later waits
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$pm = new SwooleTest\ProcessManager();
$pm->parentFunc = function () use ($pm) {
    $client = new Swoole\Client(SWOOLE_SOCK_TCP);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 10));
    $client->send('run');
    Assert::same($client->recv(), 'OK');
    $client->close();
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1,
        'reactor_num' => 1,
        'task_worker_num' => 2,
        'enable_coroutine' => false,
        'log_file' => '/dev/null',
    ]);
    $server->on('workerStart', function ($server, $id) use ($pm) {
        if ($id === 0) {
            $pm->wakeup();
        }
    });
    $server->on('receive', function ($server, $fd) {
        Assert::false(@$server->taskWaitMulti(['old-a', 'old-b'], 0.02));
        $results = $server->taskWaitMulti(['new-a', 'new-b'], 5);
        Assert::same($results[0], 'new-a');
        Assert::same($results[1], 'new-b');

        Assert::false(@$server->taskWaitMulti(['old-c', 'old-d'], 0.02));
        Assert::same($server->taskwait('single', 5), 'single');

        Assert::false(@$server->taskwait('old-single', 0.02));
        $results = $server->taskWaitMulti(['new-c', 'new-d'], 5);
        Assert::same($results[0], 'new-c');
        Assert::same($results[1], 'new-d');
        $server->send($fd, 'OK');
    });
    $server->on('task', function ($server, $id, $source, $data) {
        // Both old and new tasks stay in flight long enough to expose slot reuse.
        usleep(300000);
        return $data;
    });
    $server->on('finish', function () {});
    $server->start();
};
$pm->setWaitTimeout(15);
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
