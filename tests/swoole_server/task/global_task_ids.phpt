--TEST--
swoole_server/task: task IDs are unique across event workers
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Client;
use Swoole\Server;
use SwooleTest\ProcessManager;

$pm = new ProcessManager();
$pm->parentFunc = function () use ($pm) {
    $ids = [];
    $workers = [];
    try {
        for ($i = 0; $i < 16; $i++) {
            $client = new Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
            $client->set(['open_eof_check' => true, 'package_eof' => "\n"]);
            Assert::true($client->connect('127.0.0.1', $pm->getFreePort(), 2));
            Assert::same($client->send("task-$i\n"), strlen("task-$i\n"));
            $result = json_decode($client->recv(), true);
            $client->close();
            Assert::true(is_int($result['task_id']) && $result['task_id'] >= 0);
            $ids[] = $result['task_id'];
            $workers[$result['worker_id']] = true;
        }
        Assert::same(count($workers), 2);
        Assert::same(count(array_unique($ids)), count($ids));
    } finally {
        $pm->kill();
    }
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set([
        'worker_num' => 2,
        'task_worker_num' => 2,
        'dispatch_mode' => 1,
        'enable_coroutine' => false,
        'open_eof_split' => true,
        'package_eof' => "\n",
        'log_file' => '/dev/null',
    ]);
    $server->on('WorkerStart', function (Server $server, int $workerId) use ($pm) {
        if ($workerId === 0) {
            $pm->wakeup();
        }
    });
    $server->on('Receive', function (Server $server, int $fd, int $reactorId, string $data) {
        $taskId = $server->task($data);
        Assert::true(is_int($taskId));
        $server->send($fd, json_encode(['worker_id' => $server->worker_id, 'task_id' => $taskId]) . "\n");
    });
    $server->on('Task', function (Server $server, int $taskId, int $workerId, string $data) {
        return $data;
    });
    $server->on('Finish', function () {});
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
