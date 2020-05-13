--TEST--
swoole_process: push
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;

$process = new Process(function(Process $worker) {

  $recv = $worker->pop();

  echo "$recv";
  usleep(20000);

  $worker->exit(0);
}, false, false);

$process->useQueue();
$pid = $process->start();

$process->push("hello worker\n");
Process::wait();
?>
--EXPECT--
hello worker
