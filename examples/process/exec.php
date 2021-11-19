<?php
$process = new Swoole\Process('callback_function', true);
$pid = $process->start();

function callback_function(Swoole\Process $worker)
{
    $worker->exec('/usr/local/bin/php', array(__DIR__.'/stdin_stdout.php'));
}

echo "From Worker: ".$process->read();
$process->write("hello worker\n");
echo "From Worker: ".$process->read();

$ret = Swoole\Process::wait();
var_dump($ret);
