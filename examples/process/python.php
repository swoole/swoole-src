<?php
$process = new swoole_process('pyhon_process', true);
$pid = $process->start();

function pyhon_process(swoole_process $worker)
{
    $worker->exec('/usr/bin/python', array("echo.py"));
}

$process->write("hello world\n");
echo $process->read();

$ret = swoole_process::wait();
var_dump($ret);

