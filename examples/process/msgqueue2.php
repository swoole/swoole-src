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
$process->useQueue(ftok(__FILE__, 1), 2 | swoole_process::IPC_NOWAIT);

$send_bytes = 0;
foreach(range(1, 10) as $i)
{
    $data = str_repeat('A', 65535);
//    $data = "hello worker[$i]\n";
    $send_bytes += strlen($data);
    $process->push($data);
}

$recv_bytes = 0;
$r_data = true;
while($r_data)
{
    $r_data = $process->pop();
    $recv_bytes += $r_data;
}
echo "send={$send_bytes}, recv=$recv_bytes\n";
var_dump($process->statQueue());
