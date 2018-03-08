--TEST--
swoole_process: write in worker
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0
--FILE--
<?php
$serv = new \swoole_server('127.0.0.1', 9501);
$process = new \Swoole\Process(function ($process) use ($serv) {
    sleep(1);
    echo "process start\n";
    for ($i = 0; $i < 1024; $i++)
    {
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
$serv->on("WorkerStart", function (\swoole_server $serv) use ($process) {
    for ($i = 0; $i < 1024; $i++)
    {
        $process->write(str_repeat('A', 8192));
        assert($process==true);
    }
    echo "worker end\n";
});
$serv->on("Receive", function (\swoole_server $serv, $fd, $rid, $data) use ($process) {

});
$serv->addProcess($process);
$serv->start();
?>
--EXPECT--
worker end
process start
process end
