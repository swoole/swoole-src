<?php
$redirect_stdout = false;
$workers = [];
$worker_num = 1;

//Swoole\Process::daemon(0, 1);
for($i = 0; $i < $worker_num; $i++)
{
    $process = new Swoole\Process('child_async', $redirect_stdout);
    $process->id = $i;
    $pid = $process->start();
    $workers[$pid] = $process;
    //echo "Master: new worker, PID=".$pid."\n";
}

master_async($workers);
//master_sync($workers);

//异步主进程
function master_async($workers)
{
    Swoole\Process::signal(SIGCHLD, function ($signo) use (&$workers) {
        while(1)
        {
            $ret = Swoole\Process::wait(false);
            if ($ret)
            {
                $pid = $ret['pid'];
                $child_process = $workers[$pid];
                //unset($workers[$pid]);
                echo "Worker Exit, kill_signal={$ret['signal']} PID=" . $pid . PHP_EOL;
                $new_pid = $child_process->start();
                $workers[$new_pid] = $child_process;
                unset($workers[$pid]);
            }
            else
            {
                break;
            }
        }
    });

    /**
     * @var $process Swoole\Process
     */
    foreach($workers as $pid => $process)
    {
        Swoole\Event::add($process->pipe, function($pipe) use ($process) {
            $recv = $process->read();
            if ($recv) echo "From Worker: " . $recv;
            $process->write("HELLO worker {$process->pid}\n");
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

function child_sync(Swoole\Process $worker)
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

function child_async(Swoole\Process $worker)
{
    //echo "Worker: start. PID=".$worker->pid."\n";
    //recv data from master
    $GLOBALS['worker'] = $worker;
    global $argv;
    $worker->name("{$argv[0]}: worker #".$worker->id);

    Swoole\Process::signal(SIGTERM, function($signal_num) use ($worker) {
		echo "signal call = $signal_num, #{$worker->pid}\n";
    });

//    Swoole\Timer::tick(2000, function () use ($worker)
//    {
//        if (rand(1, 3) % 2) {
//            $worker->write("hello master {$worker->pid}\n");
//        }
//    });

    Swoole\Event::add($worker->pipe, function($pipe) use($worker) {
        $recv = $worker->read();
        echo "From Master: $recv\n";
        //$worker->write("hello master\n");
    });
}
