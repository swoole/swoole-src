<?php
$workers = [];
$worker_num = 2;

//swoole_process::daemon(0, 1);

function onReceive($pipe) {
    global $workers;
    $worker = $workers[$pipe];
    $data = $worker->read();
    if ($data == false)
    {
        //表示子进程已关闭，回收它
        $status = swoole_process::wait();
        echo "Worker#{$status['pid']} exit\n";
    }
    else
    {
        echo "RECV: ".$data;
    }
}

for($i = 0; $i < $worker_num; $i++)
{
    $process = new swoole_process('worker');
    $process->id = $i;
    $pid = $process->start();
    $workers[$process->pipe] = $process;
}

foreach($workers as $process)
{
    swoole_event_add($process->pipe, 'onReceive');
}

function worker($process)
{
    $i = 1;
    while($i++)
    {
        $process->write("Worker#{$process->id}: hello master\n");
        if ($i > 5 and $process->id == 1) $process->exit();
        sleep(1);
    }
}
