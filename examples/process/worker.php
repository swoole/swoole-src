<?php
$redirect_stdout = false;
$process = new swoole_process('callback_function', $redirect_stdout);
$worker_pid = $process->start();
echo "New worker, PID=".$worker_pid.PHP_EOL;

function callback_function($worker)
{
    echo "WorkerStart. PID=".$worker->pid."\n";
    //send data to master
    $worker->write("hello world\n");

    //recv data from master
    $recv = $worker->read();

    echo "Worker Receive: $recv\n";
    $worker->exit(0);
}
echo "Master Receive: ".$process->read();
$process->write("master");
$ret = swoole_process::wait();
var_dump($ret);
unset($process);
sleep(1);