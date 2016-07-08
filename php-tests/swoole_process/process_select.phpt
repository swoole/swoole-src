--TEST--
Test of swoole_process select
--SKIPIF--
<?php include "skipif.inc"; ?>
--FILE--
<?php
$process = new swoole_process(function (swoole_process $worker)
{
    $worker->write("hello master\n");
    $worker->exit(0);
}, false);

$pid = $process->start();
$r = array($process);
$ret = swoole_select($r, null, null, 1.0);
echo $process->read();
?>
Done
--EXPECTREGEX--
hello master
Done.*
--CLEAN--
