--TEST--
swoole_process: setaffinity
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
$r = \swoole_process::setaffinity([0]);
assert($r);

$r = \swoole_process::setaffinity([0, 1]);
assert($r);
echo "SUCCESS";
?>
--EXPECT--
SUCCESS