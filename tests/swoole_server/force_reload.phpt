--TEST--
swoole_server: force reload in process mode
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (swoole_cpu_num() === 1) {
    skip('not support on machine with single cpu');
}
?>
--FILE--
<?php
error_reporting(0);
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    $client = new swoole_client(SWOOLE_SOCK_TCP);
    if (!$client->connect('127.0.0.1', $pm->getFreePort()))
    {
        exit("connect failed\n");
    }
    $client->send("hello world");
    sleep(2);
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort());
    $serv->set([
        "worker_num" => 4,
        "max_wait_time" => 1,
    ]);
    $serv->on("WorkerStart", function (\swoole_server $server, $worker_id) use ($pm) {
        $pm->wakeup();
        echo "$worker_id [".$server->worker_pid."] start\n";
        if ($worker_id == 1) {
            $server->after(500, function () use ($server, $worker_id) {
                echo "$worker_id [" . $server->worker_pid . "] start to reload\n";
                $server->reload();
            });
        }
    });
    $serv->on('receive', function ($serv, $fd, $tid, $data) {
        if ($data) {
            sleep(10);
        }
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
%d [%d] start
%d [%d] start
%d [%d] start
%d [%d] start
%s start to reload
[%s]	NOTICE	Server is reloading all workers now.
[%s]	WARNING	swManager_kill_timeout_process (ERROR 9012): [Manager] Worker#%d[pid=%d] exit timeout, forced kill.
[%s]	WARNING	swManager_kill_timeout_process (ERROR 9012): [Manager] Worker#%d[pid=%d] exit timeout, forced kill.
[%s]	WARNING	swManager_kill_timeout_process (ERROR 9012): [Manager] Worker#%d[pid=%d] exit timeout, forced kill.
[%s]	WARNING	swManager_kill_timeout_process (ERROR 9012): [Manager] Worker#%d[pid=%d] exit timeout, forced kill.
[%s]	WARNING	swManager_check_exit_status: worker#%d[pid=%d] abnormal exit, status=0, signal=9
[%s]	WARNING	swManager_check_exit_status: worker#%d[pid=%d] abnormal exit, status=0, signal=9
[%s]	WARNING	swManager_check_exit_status: worker#%d[pid=%d] abnormal exit, status=0, signal=9
[%s]	WARNING	swManager_check_exit_status: worker#%d[pid=%d] abnormal exit, status=0, signal=9
%d [%d] start
%d [%d] start
%d [%d] start
%d [%d] start
[%s]	NOTICE	Server is shutdown now.
