--TEST--
Test of swoole_process push
--SKIPIF--
<?php include "skipif.inc"; ?>
--FILE--
<?php
$process = new swoole_process(function(swoole_process $worker) {

  $recv = $worker->pop();

  echo "$recv";
  sleep(2);

  $worker->exit(0);
}, false, false);

$process->useQueue();
$pid = $process->start();

$process->push("hello worker\n");
?>
--EXPECTREGEX--
hello worker
--CLEAN--
