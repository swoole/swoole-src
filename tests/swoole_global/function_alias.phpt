--TEST--
swoole_global: function alias
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

var_dump(function_exists('go') && function_exists('defer'));

?>
--EXPECTF--
bool(true)
