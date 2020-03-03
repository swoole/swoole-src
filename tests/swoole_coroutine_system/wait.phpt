--TEST--
swoole_coroutine_system: wait
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\System;
use Swoole\Process;

$process = new Process(function () {
    usleep(1000);
});
$process->start();

Coroutine\run(function () use ($process) {
    $status = System::wait();
    Assert::same($status['pid'], $process->pid);
    var_dump($status);
});

?>
--EXPECTF--
array(3) {
  ["pid"]=>
  int(%d)
  ["code"]=>
  int(0)
  ["signal"]=>
  int(0)
}
