--TEST--
swoole_server: kill task worker [SWOOLE_BASE]

--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

const PROC_NAME = 'swoole_unittest_server_task_worker';
$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    for ($i = 0; $i < 5; $i++)
    {
        //杀死进程
        shell_exec("ps aux | grep \"" . PROC_NAME . "\" |grep -v grep| awk '{ print $2}' | xargs kill");
        //判断进程是否存在
        assert(intval(shell_exec("ps aux | grep \"" . PROC_NAME . "\" |grep -v grep| awk '{ print $2}'")) > 0);
    }
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new \swoole_server("127.0.0.1", 9503, SWOOLE_BASE);
    $serv->set(["worker_num" => 1, 'log_file' => '/dev/null', 'task_worker_num' => 1,]);
    $serv->on("WorkerStart", function (\swoole_server $serv, $worker_id) use ($pm) {
        if ($worker_id = 1)
        {
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
