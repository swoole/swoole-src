--TEST--
swoole_server: kill user process [SWOOLE_PROCESS]
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require __DIR__ . "/../include/bootstrap.php";

const WORKER_PROC_NAME = 'swoole_unittest_server_user_process';
$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    for ($i = 0; $i < 1; $i++)
    {
        //杀死进程
        shell_exec("ps aux | grep \"" . WORKER_PROC_NAME . "\" |grep -v grep| awk '{ print $2}' | xargs kill");
        usleep(10000);
        //判断进程是否存在
        assert(intval(shell_exec("ps aux | grep \"" . WORKER_PROC_NAME . "\" |grep -v grep| awk '{ print $2}'")) > 0);
    }
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new \swoole_server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
//    $serv->set(
//        ['log_file' => TEST_LOG_FILE,]
//    );
    $process2 = new swoole_process(function ($worker) use ($serv) {
        global $argv;
        swoole_set_process_name(WORKER_PROC_NAME);
        swoole_process::signal(SIGTERM, function () {
            swoole_event_exit();
        });
        swoole_timer_after(200000, function ($interval) use ($worker, $serv) {
            echo "OK\n";
        });
        $pm->wakeup();
    }, false);
    $serv->addProcess($process2);
    $serv->set(["worker_num" => 2, 'log_file' => '/dev/null',]);
    $serv->on("WorkerStart", function (\swoole_server $serv, $worker_id) use ($pm) {

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
