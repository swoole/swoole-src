<?php
$process = new swoole_process('callback_function', true);
$pid = $process->start();

function callback_function(swoole_process $worker)
{
    $worker->exec('/usr/local/bin/php', array(__DIR__.'/stdin_stdout.php'));
}

echo "From Worker: ".$process->read();
$process->write("hello worker\n");
echo "From Worker: ".$process->read();

$ret = swoole_process::wait();
var_dump($ret);

