--TEST--
swoole_server: force reload in base mode
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
error_reporting(0);
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
use Swoole\Timer;

$atomic = new Swoole\Atomic(1);
$pm = new SwooleTest\ProcessManager;
$pm->setWaitTimeout(1000);
$pm->parentFunc = function ($pid) use ($pm) {
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $atomic) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set([
        'worker_num' => 2,
        'max_wait_time' => 1,
        'enable_coroutine' => false,
    ]);
    $serv->on("WorkerStart", function (Server $server, $worker_id) use ($pm, $atomic) {
        echo "$worker_id [".$server->worker_pid."] start\n";
        if ($worker_id == 0 ) {
            if ($atomic->get() == 1) {
                sleep(10);
            } else {
                $pm->wakeup();
            }
        }

        if ($worker_id == 1 and $atomic->get() == 1) {
            Timer::after(1, function () use ($server, $worker_id, $atomic) {
                $atomic->add(1);
                echo "$worker_id [" . $server->worker_pid . "] reload\n";
                $server->reload();

            });
        }
    });
    $serv->on("WorkerStop", function (Server $server, $worker_id) use ($pm, $atomic) {
        echo "$worker_id [".$server->worker_pid."] stop\n";
    });
    $serv->on('receive', function ($serv, $fd, $tid, $data) {
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
%d [%d] start
%d [%d] start
%d [%d] reload
[%s]	INFO	Server is reloading all workers now
%d [%d] stop
%d [%d] start
[%s]	WARNING	Manager::kill_timeout_process() (ERRNO 9101): worker(pid=%d, id=0) exit timeout, force kill the process
[%s]	WARNING	Server::check_worker_exit_status(): worker(pid=%d, id=0) abnormal exit, status=0, signal=9
%d [%d] start
%d [%d] stop
%d [%d] stop
