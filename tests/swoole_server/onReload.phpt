--TEST--
swoole_server: server beforeRelaod and afterReload event
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
error_reporting(0);
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
use Swoole\Atomic;

$WorkerStartAtomic = new Atomic(0);

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm,$argv) {
    sleep(2);
    $script_name = $argv[0];
    $ret = shell_exec("ps aux | grep $script_name | grep -v 'grep'");
    Assert::assert($ret != "");
    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm, $WorkerStartAtomic) {
    $serv = new Server('127.0.0.1', $pm->getFreePort());
    $serv->set([
        'log_file' => TEST_LOG_FILE,
        "worker_num" => 2,
        "task_worker_num" => 2,
        "max_wait_time" => 1,
    ]);
    $serv->on("BeforeReload", function (Server $serv) {
        var_dump("BeforeReload");
    });
    $serv->on("AfterReload", function (Server $serv) {
        var_dump("AfterReload");
    });
    $serv->on("WorkerStart", function (Server $serv, $worker_id) use ($pm, $WorkerStartAtomic) {
        $WorkerStartAtomic->add(1);
        if ($WorkerStartAtomic->get() === 4) {
            $serv->reload();
            $pm->wakeup();
        }
    });
    $serv->on('Receive', function ($serv, $fd, $tid, $data) {
    });
    $serv->on('Task', function ($serv,$task_id, $reactor_id, $params) {
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
string(12) "BeforeReload"
string(11) "AfterReload"
DONE
