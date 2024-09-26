--TEST--
swoole_process: freeQueue
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new Swoole\Process(function() {});
$r  = $proc->useQueue();
Assert::assert($r);

$proc->start();
$r  = $proc->freeQueue();
Assert::assert($r);

\Swoole\Process::wait();

?>
--EXPECT--
