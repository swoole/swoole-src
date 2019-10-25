--TEST--
swoole_server: kill worker [SWOOLE_BASE]
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_darwin();
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . "/../include/bootstrap.php";
use Swoole\Server;
const WORKER_PROC_NAME = 'swoole_unittest_server_event_worker';
$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    for ($i = 0; $i < 5; $i++)
    {
        //杀死进程
        kill_process_by_name(WORKER_PROC_NAME);
        usleep(10000);
        //判断进程是否存在
        Assert::assert(get_process_pid_by_name(WORKER_PROC_NAME) > 0);
    }
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(["worker_num" => 2, 'log_file' => '/dev/null',]);
    $serv->on("WorkerStart", function (Server $serv, $worker_id) use ($pm) {
        if ($worker_id == 0)
        {
            swoole_set_process_name(WORKER_PROC_NAME);
            $pm->wakeup();
        }
    });
    $serv->on("Receive", function (Server $serv, $fd, $reactorId, $data)
    {
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();

?>
--EXPECT--
