--TEST--
swoole_server/task: taskCo empty array, task limit, and taskWaitMulti delegation
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
        'task_worker_num' => 2,
        'enable_coroutine' => true,
        'log_file' => '/dev/null',
    ]);
    $server->on('workerStart', function ($server, $id) use ($pm) {
        if ($id === 0) {
            $pm->wakeup();
        }
    });
    $server->on('receive', function ($server, $fd) {
        Assert::false($server->taskCo([], 5));
        Assert::false($server->taskCo(range(1, 1024), 5));

        // inside a coroutine taskWaitMulti forwards to taskCo, so the warning names taskCo
        Assert::false($server->taskWaitMulti([], 5));
        Assert::false($server->taskWaitMulti(['a' => 'foo'], 5));

        $results = $server->taskCo(['foo', 'bar'], 5);
        Assert::isArray($results);
        Assert::same($results[0], 'done: foo');
        Assert::same($results[1], 'done: bar');
        $server->send($fd, 'OK');
    });
    $server->on('task', function ($server, $id, $source, $data) {
        return "done: $data";
    });
    $server->on('finish', function () {});
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECTF--
Warning: Swoole\Server::taskCo(): empty concurrent tasks in %s on line %d

Warning: Swoole\Server::taskCo(): too many concurrent tasks in %s on line %d

Warning: Swoole\Server::taskWaitMulti(): empty concurrent tasks in %s on line %d

Warning: Swoole\Server::taskWaitMulti(): only supports a list array, whose keys must be consecutive integers from 0 to count($tasks) - 1 in %s on line %d
DONE
