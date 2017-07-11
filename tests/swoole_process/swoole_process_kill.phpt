--TEST--
swoole_process: kill
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php

$proc = new \swoole_process(function() {
    sleep(PHP_INT_MAX);
});
$pid = $proc->start();
swoole_process::kill($pid, SIGKILL);
$i = \swoole_process::wait(true);
assert($i["signal"] === SIGKILL);
echo "SUCCESS";
?>
--EXPECT--
SUCCESS