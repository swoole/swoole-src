--TEST--
swoole_server/task: taskCo keeps result positions when some tasks fail to pack
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
        // /dev/null passes the readability check in swoole_set_task_tmpdir(), but mkstemp()
        // inside it always fails with ENOTDIR. Only payloads too big to inline need a
        // tmpfile, so this makes exactly the oversized tasks fail while small ones succeed.
        'task_tmpdir' => '/dev/null',
    ]);
    $server->on('workerStart', function ($server, $id) use ($pm) {
        if ($id === 0) {
            $pm->wakeup();
        }
    });
    $server->on('receive', function ($server, $fd) {
        $big = str_repeat('L', 65536);
        $results = $server->taskCo(['s0', $big, 's2', $big, 's4'], 5);

        Assert::isArray($results);
        Assert::count($results, 5);
        Assert::same($results[0], 'done: s0');
        Assert::false($results[1]);
        Assert::same($results[2], 'done: s2');
        Assert::false($results[3]);
        Assert::same($results[4], 'done: s4');
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
Warning: Swoole\Server::taskCo(): large task pack failed in %s on line %d

Warning: Swoole\Server::taskCo(): failed to pack task in %s on line %d

Warning: Swoole\Server::taskCo(): large task pack failed in %s on line %d

Warning: Swoole\Server::taskCo(): failed to pack task in %s on line %d
DONE
