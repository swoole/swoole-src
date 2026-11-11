--TEST--
swoole_server/task: finish requires a live task context and rejects returned frames
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$pm = new SwooleTest\ProcessManager();
$checked = new Swoole\Atomic();
$pm->parentFunc = function () use ($pm) {
    $client = new Swoole\Client(SWOOLE_SOCK_TCP);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 5));
    $client->send('run');
    $reply = '';
    while (substr_count($reply, "\n") < 2) {
        $data = $client->recv();
        Assert::notEmpty($data);
        $reply .= $data;
    }
    $lines = explode("\n", trim($reply));
    sort($lines);
    Assert::same($lines, ['outside', 'reply']);
    $client->close();
    $pm->kill();
};
$pm->childFunc = function () use ($pm, $checked) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 1,
        'reactor_num' => 1,
        'task_worker_num' => 1,
        'enable_coroutine' => false,
        'log_file' => '/dev/null',
    ]);
    $server->on('workerStart', function ($server) use ($pm, $checked) {
        if ($server->taskworker) {
            Assert::false(@$server->finish('before any task'));
            $checked->set(1);
        } else {
            $pm->wakeup();
        }
    });
    $server->on('receive', function ($server, $fd) {
        Assert::notSame($server->task($fd), false);
    });
    $server->on('task', function ($server, $id, $source, $fd) use ($checked) {
        Assert::same($checked->get(), 1);
        Assert::true($server->finish($fd));
        Swoole\Timer::after(100, function () use ($server, $fd) {
            Assert::false(@$server->finish('after the task returned'));
            $server->send($fd, "outside\n");
        });
    });
    $server->on('finish', function ($server, $id, $fd) {
        $server->send($fd, "reply\n");
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
echo "DONE\n";
?>
--EXPECT--
DONE
