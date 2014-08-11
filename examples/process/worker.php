<?php
$redirect_stdout = false;
$workers = [];
$worker_num = 8;

for($i = 0; $i < $worker_num; $i++)
{
    $process = new swoole_process('callback_function', $redirect_stdout);
    $pid = $process->start();
    $workers[$pid] = $process;
    //echo "Master: new worker, PID=".$pid."\n";
}

function callback_function(swoole_process $worker)
{
    //echo "Worker: start. PID=".$worker->pid."\n";
    //recv data from master
    $recv = $worker->read();

    echo "From Master: $recv\n";

    //send data to master
    $worker->write("hello master\n");

    sleep(2);
    $worker->exit(0);
}


function callback_function_async(swoole_process $worker)
{
    //echo "Worker: start. PID=".$worker->pid."\n";
    //recv data from master
    $GLOBALS['worker'] = $worker;
    swoole_event_add($worker->pipe, function($pipe) {
        $worker = $GLOBALS['worker'];
        $recv = $worker->read();

        echo "From Master: $recv\n";

        //send data to master
        $worker->write("hello master\n");

        sleep(2);

        $worker->exit(0);
    });
}


foreach($workers as $pid => $process)
{
    $process->write("hello worker[$pid]\n");
    echo "From Worker: ".$process->read();
}

for($i = 0; $i < $worker_num; $i++)
{
    $ret = swoole_process::wait();
    $pid = $ret['pid'];
    unset($workers[$pid]);
    echo "Worker Exit, PID=".$pid.PHP_EOL;
}
