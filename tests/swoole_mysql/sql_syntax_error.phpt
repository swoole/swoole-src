--TEST--
swoole_mysql: sql syntax error
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

swoole_mysql_query("select", function($mysql, $result) {
    if ($mysql->errno === 1064) {
        fprintf(STDERR, "SUCCESS\n");
    } else {
        fprintf(STDERR, "FAIL\n");
    }
    $mysql->close();
});
?>
--EXPECT--
SUCCESS
closed