<?php
$workers = [];
$worker_num = 2;

for($i = 0; $i < $worker_num; $i++)
{
    $process = new Swoole\Process('callback_function', false, false);
    $process->useQueue();
    $pid = $process->start();
    $workers[$pid] = $process;
    //echo "Master: new worker, PID=".$pid."\n";
}

function callback_function(Swoole\Process $worker)
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

while(true)
{
    /**
     * @var $process Swoole\Process
     */
    $pid = array_rand($workers);
    $process = $workers[$pid];
    $process->push("hello worker[$pid]\n");
    sleep(1);
}

for($i = 0; $i < $worker_num; $i++)
{
    $ret = Swoole\Process::wait();
    $pid = $ret['pid'];
    unset($workers[$pid]);
    echo "Worker Exit, PID=".$pid.PHP_EOL;
}
