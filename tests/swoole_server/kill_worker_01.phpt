--TEST--
swoole_server: kill worker [SWOOLE_BASE]

--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
require_once __DIR__ . "/../include/bootstrap.php";

const WORKER_PROC_NAME = 'swoole_unittest_server_event_worker';
$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    for ($i = 0; $i < 1; $i++)
    {
        //杀死进程
        shell_exec("ps aux | grep \"" . WORKER_PROC_NAME . "\" |grep -v grep| awk '{ print $2}' | xargs kill");
        //判断进程是否存在
        assert(intval(shell_exec("ps aux | grep \"" . WORKER_PROC_NAME . "\" |grep -v grep| awk '{ print $2}'")) > 0);
    }
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new \swoole_server("127.0.0.1", 9503, SWOOLE_BASE);
    $serv->set(["worker_num" => 2, 'log_file' => '/dev/null',]);
    $serv->on("WorkerStart", function (\swoole_server $serv, $worker_id) use ($pm) {
        if ($worker_id == 0)
        {
            swoole_set_process_name(WORKER_PROC_NAME);
            $pm->wakeup();
        }
    });
    $serv->on("Receive", function (\swoole_server $serv, $fd, $reactorId, $data)
    {
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();

?>

--EXPECT--
