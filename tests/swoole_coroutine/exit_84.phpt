--TEST--
swoole_coroutine: exit
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_php_version_lower_than('8.4');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
require TESTS_API_PATH . '/exit.php';
?>
--EXPECTF--
int(1)
string(4) "exit"
int(0)
