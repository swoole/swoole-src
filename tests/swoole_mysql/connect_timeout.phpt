--TEST--
swoole_mysql: connect timeout
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/../include/api/swoole_mysql/swoole_mysql_connect_timeout.php';

?>

--EXPECT--
closed