--TEST--
swoole_process: freeQueue
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
$proc = new \swoole_process(function() {});
$r  = $proc->useQueue();
assert($r);

$proc->start();
$r  = $proc->freeQueue();
assert($r);

\swoole_process::wait();

?>
--EXPECT--