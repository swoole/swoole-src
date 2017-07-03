--TEST--
swoole_async: parallel_read_copy_10m_file

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
require_once __DIR__ . "/../include/api/swoole_async/read_write.php";


$chunk = 1024 * 512;
parallel_read_copy($chunk, 10);
?>

--EXPECT--
SUCCESS

--CLEAN--