<?php
$redirect_stdout = false;
$workers = [];
$worker_num = 1;

//swoole_process::daemon(0, 1);
for($i = 0; $i < $worker_num; $i++)
{
    $process = new swoole_process('child_async', $redirect_stdout);
    $pid = $process->start();
    $workers[$pid] = $process;
    //echo "Master: new worker, PID=".$pid."\n";
}

master_async($workers);
//master_sync($workers);

//异步主进程
function master_async($workers)
{
    swoole_process::signal(SIGCHLD, function ($signo) use ($workers) {
        $ret = swoole_process::wait();
        $pid = $ret['pid'];
        unset($workers[$pid]);
        echo "Worker Exit, PID=" . $pid . PHP_EOL;
    });

    /**
     * @var $process swoole_process
     */
    foreach($workers as $pid => $process)
    {
        swoole_event_add($process->pipe, function($pipe) use ($process) {
            $recv = $process->read();
            if ($recv) echo "From Worker: " . $recv;
        });
        $process->write("hello worker[$pid]\n");
    }
}

//同步主进程
function master_sync($workers)
{
    foreach($workers as $pid => $process)
    {
        $process->write("hello worker[$pid]\n");
        echo "From Worker: ".$process->read();
    }
}

function child_sync(swoole_process $worker)
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

function child_async(swoole_process $worker)
{
    //echo "Worker: start. PID=".$worker->pid."\n";
    //recv data from master
    $GLOBALS['worker'] = $worker;
    global $argv;
    $worker->name("{$argv[0]}: worker");
    swoole_process::signal(SIGTERM, function($signal_num) use ($worker) {
		echo "signal call = $signal_num, #{$worker->pid}\n";
    });

    swoole_event_add($worker->pipe, function($pipe) use($worker) {
        $recv = $worker->read();
        echo "From Master: $recv\n";
        $worker->write("hello master\n");
    });
}
