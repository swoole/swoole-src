--TEST--
swoole_coroutine_system: wait
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

$process = new Process(function () use ($atomic) {
    $atomic->wait(10);
});
$process->start();

Coroutine\run(function () use ($process, $atomic) {
    for ($n = MAX_REQUESTS; $n--;) {
        $status = System::wait(0.001);
        Assert::false($status);
        Assert::same(swoole_last_error(), SOCKET_ETIMEDOUT);
    }
    $atomic->wakeup();
    $status = System::wait(1);
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
