<?php
function callback_function(swoole_process $worker)
{
    //echo "Worker: start. PID=".$worker->pid."\n";
    //recv data from master
    while(true)
    {
        $recv = $worker->pop();
        echo "From Master: $recv\n";
    }

    sleep(2);
    $worker->exit(0);
}

$process = new swoole_process('callback_function', false, false);
$process->useQueue();

$bytes = 0;
foreach(range(1, 10) as $i)
{
    $data = "hello worker[$i]\n";
    $bytes += strlen($data);
    $process->push($data);
}

echo "bytes={$bytes}\n";
var_dump($process->statQueue());
