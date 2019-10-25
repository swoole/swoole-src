--TEST--
swoole_server/task: kill task worker [SWOOLE_BASE]
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_darwin();
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\Server;
const PROC_NAME = 'swoole_unittest_server_task_worker';
$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    for ($i = 0; $i < 5; $i++)
    {
        //杀死进程
        kill_process_by_name(PROC_NAME);
        usleep(10000);
        //判断进程是否存在
        Assert::assert(get_process_pid_by_name(PROC_NAME) > 0);
    }
    $cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    $cli->connect('127.0.0.1', $pm->getFreePort(), 10) or die("ERROR");
    $cli->send("task-01") or die("ERROR");
    Assert::same($cli->recv(), "task-01");
    $cli->close();
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(["worker_num" => 1, 'log_file' => TEST_LOG_FILE, 'task_worker_num' => 1,]);
    $serv->on("WorkerStart", function (Server $serv, $worker_id) use ($pm) {
        if ($worker_id = 1) {
            swoole_set_process_name(PROC_NAME);
            $pm->wakeup();
        }
    });
    $serv->on("Receive", function (Server $serv, $fd, $reactorId, $data)
    {
        $serv->task(['fd' => $fd, 'data' => $data]);
    });
    $serv->on('task', function (Server $serv, $task_id, $worker_id, $data)
    {
        $serv->send($data['fd'], $data['data']);
    });
    $serv->on('finish', function (Server $serv, $fd, $rid, $data)
    {
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();

?>
--EXPECT--
