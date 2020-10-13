--TEST--
swoole_server: send 2M data in task worker
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const SIZE = 2 * 1024 * 1024;

use Swoole\Server;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    for ($i = 0; $i < MAX_CONCURRENCY_MID; $i++) {
        go(function () use ($pm, $i) {
            $cli = new Co\Client(SWOOLE_SOCK_TCP);
            $cli->set([
                'open_length_check' => true,
                'package_max_length' => 4 * 1024 * 1024,
                'package_length_type' => 'N',
                'package_length_offset' => 0,
                'package_body_offset' => 4,
            ]);
            if ($cli->connect('127.0.0.1', $pm->getFreePort(), 2) == false) {
                echo "ERROR\n";
                return;
            }
            for ($i = 0; $i < MAX_REQUESTS; $i++) {
                $sid = strval(rand(10000000, 99999999));
                $send_data = str_repeat('A', 1000) . $sid;
                $cli->send(pack('N', strlen($send_data)) . $send_data);
                $data = $cli->recv();
                Assert::same(strlen($data), SIZE);
                Assert::same($sid, substr($data, -8, 8));
            }
        });
    }
    Swoole\Event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set(array(
        "worker_num" => 2,
        'log_level' => SWOOLE_LOG_ERROR,
        'task_worker_num' => 2,
        'open_length_check' => true,
        'package_max_length' => 4 * 1024 * 1024,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 4,
        'task_use_object' => true,
    ));
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data) {
        $serv->task(['fd' => $fd, 'data' => $data]);
    });
    $serv->on('task', function (Server $serv, Server\Task $task) {
        $send_data = str_repeat('A', SIZE - 12) . substr($task->data['data'], -8, 8);
        Assert::true($serv->send($task->data['fd'], pack('N', strlen($send_data)) . $send_data));
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
