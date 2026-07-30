--TEST--
swoole_server/task: finish serialization exception
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Client;
use Swoole\Server;
use Swoole\Server\Task;
use SwooleTest\ProcessManager;

$pm = new ProcessManager();

$pm->parentFunc = function () use ($pm) {
    $client = new Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $client->set([
        'package_eof'    => "\r\n",
        'open_eof_check' => true,
        'open_eof_split' => true,
    ]);
    Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 10));
    Assert::greaterThan($client->send("START\r\n"), 0);
    echo $client->recv();
    $client->close();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
    $server->set([
        'log_file'              => '/dev/null',
        'worker_num'            => 1,
        'task_worker_num'       => 1,
        'task_enable_coroutine' => true,
        'package_eof'           => "\r\n",
        'open_eof_check'        => true,
    ]);
    $server->on('workerStart', function (Server $server, int $workerId) use ($pm) {
        if ($workerId === 0) {
            $pm->wakeup();
        }
    });
    $server->on('receive', function (Server $server, int $fd) {
        Assert::integer($server->task($fd));
    });
    $server->on('task', function (Server $server, Task $task) {
        $markers = [];

        try {
            $task->finish([1, $server]);
        } catch (Throwable $exception) {
            Assert::contains($exception->getMessage(), 'Serialization');
            $markers[] = 'NESTED';
        }

        try {
            $task->finish($server);
        } catch (Throwable $exception) {
            Assert::contains($exception->getMessage(), 'Serialization');
            $markers[] = 'ROOT';
        }

        $markers[] = 'OK';
        Assert::true($task->finish([$task->data, $markers]));
    });
    $server->on('finish', function (Server $server, int $taskId, array $result) {
        [$fd, $markers] = $result;
        Assert::true($server->send($fd, implode("\n", $markers) . "\r\n"));
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
NESTED
ROOT
OK
