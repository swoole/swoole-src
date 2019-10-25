--TEST--
swoole_server: force reload
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
error_reporting(0);
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$atomic = new swoole_atomic(1);

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm,$argv) {
    sleep(2);
    $script_name = $argv[0];
    $ret = shell_exec("ps aux | grep $script_name | grep -v 'grep'");
    Assert::assert($ret != "");
    $pm->kill();
};

$pm->childFunc = function () use ($pm,$atomic) {
    $flag = 0;
    $flag1 = 0;
    $serv = new Server('127.0.0.1', $pm->getFreePort());
    $serv->set([
        'log_file' => TEST_LOG_FILE,
        "worker_num" => 2,
        "task_worker_num" => 1,
        "max_wait_time" => 1
    ]);
    $serv->on("WorkerStart", function (Server $server, $worker_id) use ($pm, $atomic) {
        $pm->wakeup();
        $server->after(50,function() use ($server, $worker_id, $atomic){
            if ($atomic->get() == 1) {
                $atomic->add(1);
                $server->reload();
            }            
        });
    });
    $serv->on('receive', function ($serv, $fd, $tid, $data) {
    });
    $serv->on('task', function ($serv,$task_id, $reactor_id, $params) {
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
