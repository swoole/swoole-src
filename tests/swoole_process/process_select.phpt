--TEST--
swoole_process: select
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
$process = new swoole_process(function (swoole_process $worker)
{
    $worker->write("hello master\n");
    $worker->exit(0);
}, false);

$pid = $process->start();
$r = array($process);
$w = array();
$e = array();
$ret = swoole_select($r, $w, $e, 1.0);
echo $process->read();
?>
Done
--EXPECTREGEX--
hello master
Done.*
--CLEAN--
