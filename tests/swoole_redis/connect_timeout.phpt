--TEST--
swoole_redis: connect timeout

--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc";
if (!class_exists("swoole_redis", false))
{
    exit("required redis.");
}
?>

--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . "/../include/api/swoole_redis/connect_timeout.php";

?>

--EXPECT--
