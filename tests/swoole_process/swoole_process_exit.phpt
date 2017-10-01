--TEST--
swoole_process: exit
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
    $proc->exit(9);
});
$pid = $proc->start();


$i = \swoole_process::wait(true);
assert($i["code"] === 9);

echo "SUCCESS";
?>
--EXPECT--
SUCCESS