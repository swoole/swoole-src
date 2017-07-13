--TEST--
swoole_mysql: test refcount
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__."/../include/api/swoole_mysql/swoole_mysql_init.php";
fork_exec(function() {
    require_once __DIR__ . "/../include/api/swoole_mysql/swoole_mysql_refcout.php";
});
?>
--EXPECT--
SUCCESS
