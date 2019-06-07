--TEST--
swoole_process: freeQueue
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new \swoole_process(function() {});
$r  = $proc->useQueue();
Assert::assert($r);

$proc->start();
$r  = $proc->freeQueue();
Assert::assert($r);

\swoole_process::wait();

?>
--EXPECT--
