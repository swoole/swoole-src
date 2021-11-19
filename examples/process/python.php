<?php
$process = new Swoole\Process('pyhon_process', true);
$pid = $process->start();

function pyhon_process(Swoole\Process $worker)
{
    $worker->exec('/usr/bin/python', array("echo.py"));
}

$process->write("hello world\n");
echo $process->read();

$ret = Swoole\Process::wait();
var_dump($ret);
