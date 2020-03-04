--TEST--
swoole_coroutine_system: waitPid
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Coroutine;
use Swoole\Coroutine\System;
use Swoole\Process;

$atomic = new Atomic;

$processFast = new Process(function () {
    usleep(1000);
});
$processFast->start();

$processSlow = new Process(function () use ($atomic) {
    $atomic->wait(10);
    usleep(10 * 1000);
});
$processSlow->start();

Coroutine\run(function () use ($processFast, $processSlow, $atomic) {
    for ($n = MAX_REQUESTS; $n--;) {
        $status = System::waitPid($processSlow->pid, 0.001);
        Assert::false($status);
        Assert::same(swoole_last_error(), SOCKET_ETIMEDOUT);
    }
    $atomic->wakeup();
    $status = System::waitPid($processSlow->pid, 1);
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
