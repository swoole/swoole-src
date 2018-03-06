--TEST--
swoole_mysql: select 1
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
    swoole_mysql_query("select 1", function($mysql_result, $result) {
        swoole_event_exit();
        fprintf(STDERR, "SUCCESS\n");
    });
});
?>
--EXPECT--
SUCCESS
closed