--TEST--
swoole_process: useQueue
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php

$proc = new \swoole_process(function(\swoole_process $proc) {
    echo $proc->pop();
});
$proc->useQueue();
$proc->start();
$proc->push("SUCCESS");

\swoole_process::wait(true);
$proc->freeQueue();
?>
--EXPECT--
SUCCESS