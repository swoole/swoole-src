<?php
$process = new swoole_process(function (swoole_process $worker)
{
    echo "Worker: start. PID=" . $worker->pid . "\n";
    sleep(2);
    $worker->close(swoole_process::PIPE_READ);
    $worker->write("hello master\n");
    $worker->exit(0);
}, false);

$pid = $process->start();
$r = array($process);
$w = array();
$e = array();
$ret = swoole_select($r, $w, $e, 1.0);
var_dump($ret);
var_dump($process->read());
