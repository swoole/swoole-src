--TEST--
swoole_async: recursive write file

--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/swoole_async/recursive_write.php';

recursiveWrite();
?>
--EXPECT--
SUCCESS