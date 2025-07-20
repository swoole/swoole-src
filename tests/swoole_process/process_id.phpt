--TEST--
swoole_process: Github bug #5825
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;
for ($n = 1; $n <= 3; $n++) {
    $process = new Process(function ($process) use ($n) {
        Assert::same($process->id, $n);
    });
    Assert::same($process->id, $n);
    $process->start();
}
?>
--EXPECT--
