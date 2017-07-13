--TEST--
swoole_process: push
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php

//$proc = new \swoole_process(swoole_function() {});
//$proc->useQueue();
//$r = $proc->push("\0");
// assert($r === false);
// TODO max data ?
// $r = $proc->push(str_repeat("\0", 1024 * 1024 * 8));
// assert($r === false);
//$proc->freeQueue();


$proc = new \swoole_process(function() {});
$proc->useQueue();
$proc->start();
$r = $proc->push("\0");
assert($r === true);
$proc->freeQueue();
\swoole_process::wait(true);
echo "SUCCESS";
?>
--EXPECT--
SUCCESS