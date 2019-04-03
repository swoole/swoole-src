--TEST--
swoole_server: force reload in base mode
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
error_reporting(0);
require __DIR__ . '/../include/bootstrap.php';

$atomic = new swoole_atomic(1);
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    sleep(2);
    $pm->kill();
};

$pm->childFunc = function () use ($pm,$atomic) {
    $flag = 0;
    $flag1 = 0;
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set([
        "worker_num" => 2,
        "max_wait_time" => 1
    ]);
    $serv->on("WorkerStart", function (\swoole_server $server, $worker_id) use ($pm, $atomic) {
        $pm->wakeup();        
        echo "$worker_id [".$server->worker_pid."] start \n";
        if ($worker_id == 0 and $atomic->get() == 1) {
            $flag = 1;
            sleep(10);
        }
        if ($worker_id == 1 and $atomic->get() == 1) {           
            $server->after(1,function() use ($server, $worker_id, $atomic){
                $atomic->add(1);
                echo "$worker_id [".$server->worker_pid."] start to reload\n";
                $server->reload();                
            });
        }
    });
    $serv->on('receive', function ($serv, $fd, $tid, $data) {
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
%s
%s
1 [%s] start to reload
[%s]	INFO	reload workers
[%s]	WARNING	swProcessPool_killTimeout: swKill(%d, SIGKILL) [%d]
[%s]	WARNING	swProcessPool_killTimeout: swKill(%d, SIGKILL) [%d]
[%s]	WARNING	swProcessPool_wait: worker#%d abnormal exit, status=0, signal=9
[%s]	WARNING	swProcessPool_wait: worker#%d abnormal exit, status=0, signal=9
%s
%s
[%s]	INFO	Server is shutdown now
