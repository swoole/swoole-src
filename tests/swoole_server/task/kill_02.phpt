--TEST--
swoole_server/task: kill task worker 01 [SWOOLE_BASE]
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_darwin();
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

const PROC_NAME = 'swoole_unittest_server_task_worker';
$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    for ($i = 0; $i < 5; $i++)
    {
        //杀死进程
        kill_process_by_name(PROC_NAME);
        usleep(10000);
        //判断进程是否存在
        assert(get_process_pid_by_name(PROC_NAME) > 0);
    }
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new \swoole_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(["worker_num" => 1, 'log_file' => TEST_LOG_FILE, 'task_worker_num' => 1,]);
    $serv->on("WorkerStart", function (\swoole_server $serv, $worker_id) use ($pm) {
        if ($worker_id = 1) {
            swoole_set_process_name(PROC_NAME);
            $pm->wakeup();
        }
    });
    $serv->on("Receive", function (\swoole_server $serv, $fd, $reactorId, $data)
    {
    });
    $serv->on('task', function (swoole_server $serv, $task_id, $worker_id, $data)
    {
        return array("code" => 0, 'message' => 'hello world', 'sid' => uniqid());
    });
    $serv->on('finish', function (swoole_server $serv, $fd, $rid, $data)
    {
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();

?>
--EXPECT--
