--TEST--
swoole_http_client: connect_host_not_found

--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
require_once __DIR__ . "/../include/api/swoole_http_client/connect_host_not_found.php";
// 实际期望输出error
?>

--EXPECT--
error