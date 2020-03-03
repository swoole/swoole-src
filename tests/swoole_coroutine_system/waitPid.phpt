--TEST--
swoole_coroutine_system: waitPid
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\System;
use Swoole\Process;

$processFast = new Process(function () {
    usleep(1000);
});
$processFast->start();

$processSlow = new Process(function () {
    usleep(10 * 1000);
});
$processSlow->start();

Coroutine\run(function () use ($processFast, $processSlow) {
    $status = System::waitPid($processSlow->pid);
    Assert::same($status['pid'], $processSlow->pid);
    var_dump($status);
    $status = System::waitPid($processFast->pid);
    Assert::same($status['pid'], $processFast->pid);
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
array(3) {
  ["pid"]=>
  int(%d)
  ["code"]=>
  int(0)
  ["signal"]=>
  int(0)
}
