--TEST--
swoole_mysql: connect_twice
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_docker('foreign network dns error');
?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

fork_exec(function() {
    require_once __DIR__ . '/../include/api/swoole_mysql/swoole_mysql_connect_twice.php';
});
?>
--EXPECT--
SUCCESS
closed
