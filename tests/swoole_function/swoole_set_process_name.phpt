--TEST--
swoole_set_process_name

--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
<?php require  __DIR__ . "/../inc/skipifDarwin.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0


--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";

$name = "SWOOLE_PROCESS_TEST_" . rand(1, 100);
swoole_set_process_name($name);
$count = trim(`ps aux|grep $name|grep -v grep|wc -l`);
assert($count == 1);
echo "SUCCESS";

?>

--EXPECT--
SUCCESS
