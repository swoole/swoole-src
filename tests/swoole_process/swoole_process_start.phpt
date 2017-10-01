--TEST--
swoole_process: start
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
    echo "SUCCESS";
});
$r = $proc->start();
assert($r > 0);
$proc->close();

\swoole_process::wait(true);
?>
--EXPECT--
SUCCESS