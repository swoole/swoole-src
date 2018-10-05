--TEST--
swoole_async: parallel_read_copy_10m_file

--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../include/api/swoole_async/read_write.php';

$chunk = 1024 * 1024;
parallel_read_copy($chunk, 10);
?>
--EXPECT--
SUCCESS

--CLEAN--