<?php
$workers = [];
$worker_num = 10;

//swoole_process::daemon(0, 1);

function onReceive($pipe) {
    global $workers;
    $worker = $workers[$pipe];
    $data = $worker->read();
    echo "RECV: " . $data;
}

//循环创建进程
for($i = 0; $i < $worker_num; $i++)
{
    $process = new swoole_process(function(swoole_process $process) {
        $i = 1;
        while($i++)
        {
            $process->write("Worker#{$process->id}: hello master\n");
            if ($i > 5 and $process->id == 1) $process->exit();
            sleep(1);
        }
    });
    $process->id = $i;
    $pid = $process->start();
    $workers[$process->pipe] = $process;
}

swoole_process::signal(SIGCHLD, function(){
    //表示子进程已关闭，回收它
    $status = swoole_process::wait();
    echo "Worker#{$status['pid']} exit\n";
});

//将子进程的管道加入EventLoop
foreach($workers as $process)
{
    swoole_event_add($process->pipe, 'onReceive');
}
