--TEST--
swoole_process: write in worker
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $serv = new \swoole_server('127.0.0.1', $pm->getFreePort());
    $process = new \swoole_process(function (swoole_process $process) use ($serv) {
        echo "process start\n";
        for ($i = 0; $i < 1024; $i++) {
            $data = $process->read();
            Assert::eq(strlen($data), 8192);
        }
        echo "process end\n";
    });
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
    ]);
    $serv->on("WorkerStart", function (\swoole_server $serv) use ($process, $pm) {
        usleep(1);
        for ($i = 0; $i < 1024; $i++) {
            $process->write(str_repeat('A', 8192));
            Assert::true($process);
        }
        switch_process();
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
