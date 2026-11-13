--TEST--
swoole_server/task: taskWaitMulti rejects every form of empty task array
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
        'enable_coroutine' => false,
        'log_file' => '/dev/null',
    ]);
    $server->on('workerStart', function ($server, $id) use ($pm) {
        if ($id === 0) {
            $pm->wakeup();
        }
    });
    $server->on('receive', function ($server, $fd) {
        Assert::false($server->taskWaitMulti([], 5));
        Assert::false($server->taskWaitMulti(array(), 5));

        // an array emptied by unset() is still a list, so it must reach the empty
        // guard rather than the list guard
        $emptiedList = ['x'];
        unset($emptiedList[0]);
        Assert::false($server->taskWaitMulti($emptiedList, 5));

        $emptiedMap = ['k' => 'x'];
        unset($emptiedMap['k']);
        Assert::false($server->taskWaitMulti($emptiedMap, 5));

        // the rejections above must not leave anything behind that breaks a normal call
        $results = $server->taskWaitMulti(['foo', 'bar'], 5);
        Assert::isArray($results);
        Assert::count($results, 2);
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
Warning: Swoole\Server::taskWaitMulti(): empty concurrent tasks in %s on line %d

Warning: Swoole\Server::taskWaitMulti(): empty concurrent tasks in %s on line %d

Warning: Swoole\Server::taskWaitMulti(): empty concurrent tasks in %s on line %d

Warning: Swoole\Server::taskWaitMulti(): empty concurrent tasks in %s on line %d
DONE
