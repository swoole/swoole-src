--TEST--
swoole_async: recursive write file

--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . "/../include/api/swoole_async/recursive_write.php";

recursiveWrite();
?>

--EXPECT--
SUCCESS