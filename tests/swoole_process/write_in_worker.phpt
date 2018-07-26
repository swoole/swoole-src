--TEST--
swoole_process: write in worker
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_docker('unknown reason');
?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

$pm = new \ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $serv = new \swoole_server('127.0.0.1', 9501);
    $process = new \swoole_process(function (swoole_process $process) use ($serv) {
        sleep(1);
        echo "process start\n";
        for ($i = 0; $i < 1024; $i++) {
            $data = $process->read();
            assert(strlen($data) == 8192);
        }
        echo "process end\n";
        $serv->shutdown();
    });
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
    ]);
    $serv->on("WorkerStart", function (\swoole_server $serv) use ($process, $pm) {
        for ($i = 0; $i < 1024; $i++) {
            $process->write(str_repeat('A', 8192));
            assert($process == true);
        }
        echo "worker end\n";
        $pm->wakeup();
    });
    $serv->on("Receive", function () { });
    $serv->addProcess($process);
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
process start
process end
worker end
