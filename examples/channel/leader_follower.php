<?php
use Swoole\Timer;
use Swoole\Process;
use Swoole\Channel;

$chan = new Channel(1024 * 256);

$worker_num = 4;
$workers = array();

for ($i = 0; $i < $worker_num; $i++)
{
    $process = new Process(function ($worker) use ($chan, $i)
    {
        while (true)
        {
            $data = $chan->pop();
            if (empty($data))
            {
                usleep(200000);
                continue;
            }
            echo "worker#$i\t$data\n";
        }
    }, false);
    $process->id = $i;
    $pid = $process->start();
    $workers[$pid] = $process;
}

Timer::tick(2000, function () use ($chan)
{
    static $index = 0;
    $chan->push("hello-" . $index++);
});