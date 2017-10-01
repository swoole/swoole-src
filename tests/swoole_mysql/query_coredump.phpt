--TEST--
swoole_mysql: query coredump
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

swoole_mysql_query("select 1", function($swoole_mysql, $result) {
    fprintf(STDERR, "SUCCESS\n");
    $swoole_mysql->close();
});
?>
--EXPECT--
SUCCESS
closed