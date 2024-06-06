--TEST--
swoole_global: handle closed STDOUT/STDERR without exception
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
fclose(STDERR);
?>
--EXPECT--
