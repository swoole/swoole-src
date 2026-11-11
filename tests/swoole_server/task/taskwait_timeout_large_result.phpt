--TEST--
swoole_server/task: a large result arriving after taskwait timed out leaves no temporary file
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$tmpdir = sys_get_temp_dir() . '/swoole_task_timeout_' . getmypid();
@mkdir($tmpdir);

$pm = new SwooleTest\ProcessManager();
$pm->parentFunc = function () use ($pm) {
    $client = new Swoole\Client(SWOOLE_SOCK_TCP);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
    $client->send('run');
    Assert::same($client->recv(), "ok\n");
    $client->close();
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $tmpdir) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'task_worker_num' => 1,
        'task_tmpdir' => $tmpdir,
        'enable_coroutine' => false,
        'log_file' => '/dev/null',
    ]);
    $server->on('workerStart', function ($server) use ($pm) {
        if (!$server->taskworker) {
            $pm->wakeup();
        }
    });
    $server->on('receive', function ($server, $fd) use ($tmpdir) {
        Assert::false($server->taskwait(['delay' => 300000], 0.1));
        usleep(500000);
        Assert::same(count(glob($tmpdir . '/*')), 0);
        $result = $server->taskwait(['delay' => 0], 5);
        Assert::same(strlen($result), 65536);
        $server->send($fd, "ok\n");
    });
    $server->on('task', function ($server, $id, $source, $data) {
        usleep($data['delay']);
        return str_repeat('x', 65536);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
array_map('unlink', glob($tmpdir . '/*'));
@rmdir($tmpdir);
echo "DONE\n";
?>
--EXPECT--
DONE
