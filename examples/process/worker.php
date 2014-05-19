<?php
$redirect_stdout = false;
$worker = swoole_process::create('callback_function', $redirect_stdout);
$worker_pid = $worker->start();
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
echo "Master Receive: ".$worker->read();
$worker->write("master");
$ret = swoole_process::wait();
var_dump($ret);
unset($worker);
sleep(1);