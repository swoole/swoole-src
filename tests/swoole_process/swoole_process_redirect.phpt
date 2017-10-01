--TEST--
swoole_process: redirect
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
    echo "SUCCESS";
}, true);

$proc->start();
$r = $proc->read();
echo "READ: $r~";


\swoole_process::wait(true);
?>
--EXPECT--
READ: SUCCESS~