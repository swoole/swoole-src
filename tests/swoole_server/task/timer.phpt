--TEST--
swoole_server/task: timer
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine\Http\Client;
use Swoole\Server\Task;
use Swoole\WebSocket\Frame;
use Swoole\WebSocket\Server;

use function Swoole\Coroutine\run;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    run(function () use ($pm) {
        $cli = new Client('127.0.0.1', $pm->getFreePort());
        $cli->set(['websocket_compression' => true, ]);
        $cli->upgrade('/');
        $cli->push('Hello Swoole');
        $data = $cli->recv(5);
        Assert::eq($data->data, 'OK');
        echo "DONE\n";
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $http->set([
        'worker_num' => 1,
        'task_worker_num' => 1,
        'event_object' => true,
        'log_file' => '/dev/null',
    ]);
    $http->on('message', function (Server $server, Frame $frame) {
        $server->task(['fd' => $frame->fd]);
    });
    $http->on('WorkerStart', function (Server $server, int $workerId) {
        if ($server->taskworker) {
            swoole_timer_after(1, function () use ($server, $workerId) {
                var_dump("after1 : " . time());
            });
            // never callback
            swoole_timer_after(10000, function () use ($server, $workerId) {
                var_dump("after2 : " . time());
            });
        }
    });
    $http->on('task', function (Server $server, Task $task) {
        var_dump('begin : ' . time());
        swoole_timer_after(2000, function () use ($server, $task) {
            var_dump('end : ' . time());
            Assert::true($server->push($task->data['fd'], "OK"));
        });
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
string(19) "after1 : %d"
string(18) "begin : %d"
string(16) "end : %d"
DONE
