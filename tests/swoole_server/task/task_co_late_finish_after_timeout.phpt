--TEST--
swoole_server/task: taskCo discards a finish that arrives after the timeout cleanup
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
        'task_worker_num' => 4,
        'enable_coroutine' => true,
        'log_file' => '/dev/null',
    ]);
    $server->on('workerStart', function ($server, $id) use ($pm) {
        if ($id === 0) {
            $pm->wakeup();
        }
    });
    $server->on('receive', function ($server, $fd) {
        $results = $server->taskCo(['fast0', 'slow', 'fast2'], 0.5);

        Assert::isArray($results);
        Assert::count($results, 3);
        Assert::same($results[0], 'done: fast0');
        Assert::false($results[1]);
        Assert::same($results[2], 'done: fast2');

        // stay alive so the slow task's finish lands after taskCo has already returned.
        // Its map entry must be gone by then, otherwise onFinish dereferences a dead
        // TaskCo and a freed task id list.
        Co::sleep(2);
        $server->send($fd, 'OK');
    });
    $server->on('task', function ($server, $id, $source, $data) {
        if ($data === 'slow') {
            sleep(1);
        }
        return "done: $data";
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
