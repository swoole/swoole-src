--TEST--
swoole_server:
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
/**
 * Created by IntelliJ IDEA.
 * User: chuxiaofeng
 * Date: 17/6/7
 * Time: 下午4:34
 */
require_once __DIR__ . "/../include/swoole.inc";

echo "TODO";
?>
--EXPECT--
SUCCESS