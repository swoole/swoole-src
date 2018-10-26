--TEST--
swoole_async: sequence copy 10m file

--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/swoole_async/read_write.php';

serial_read_copy(10);
?>
--EXPECT--
SUCCESS

--CLEAN--