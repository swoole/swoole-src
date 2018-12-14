--TEST--
swoole_process: freeQueue
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$proc = new \swoole_process(function() {});
$r  = $proc->useQueue();
assert($r);

$proc->start();
$r  = $proc->freeQueue();
assert($r);

\swoole_process::wait();

?>
--EXPECT--