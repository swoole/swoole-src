--TEST--
Test of swoole_process msgqueue
--SKIPIF--
<?php include "skipif.inc"; ?>
--FILE--
<?php
function callback_function(swoole_process $worker){}

$process = new swoole_process('callback_function', false, false);
$process->useQueue();

$bytes = 0;
foreach(range(1, 10) as $i)
{
    $data = "hello worker[$i]";
    $bytes += strlen($data);
    $process->push($data);
}

$queue = $process->statQueue();
($queue['queue_num'] == 10 && $queue['queue_bytes'] == $bytes)
    && $output = "Success\n";

echo $output;
$process->freeQueue();
?>
Done
--EXPECTREGEX--
Success
Done.*
--CLEAN--
