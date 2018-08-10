--TEST--
swoole_function: swoole_version
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

$version = swoole_version();
echo "swoole_version: $version";

?>

--EXPECTF--
swoole_version: %s
