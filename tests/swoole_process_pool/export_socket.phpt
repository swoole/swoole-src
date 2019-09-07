--TEST--
swoole_process_pool: exportSocket
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pool = new Swoole\Process\Pool(2, SWOOLE_IPC_UNIXSOCK, 0, true);

$pool->on('workerStart', function (Swoole\Process\Pool $pool, int $workerId) {
    $process = $pool->getProcess(0);
    $socket = $process->exportSocket();
    if ($workerId == 0) {
        echo $socket->recv();
        $socket->send("hello proc1\n");
        echo "proc0 stop\n";
    } else {
        $socket->send("hello proc0\n");
        echo $socket->recv();
        echo "proc1 stop\n";
        $pool->shutdown();
    }
});

$pool->start();
?>
--EXPECT--
hello proc0
proc0 stop
hello proc1
proc1 stop
