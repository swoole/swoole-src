--TEST--
swoole_coroutine/bailout: error
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
go(function () {
    $a = str_repeat('A', 1024 * 1024 * 1024 * 1024);
    co::sleep(0.1);
});
?>
--EXPECTF--
Fatal error: Allowed memory size of %d bytes exhausted %s
--EXPECTF_85--
Fatal error: Allowed memory size of %d bytes exhausted %s
Stack trace:
#0 %s(%d): str_repeat('A', %d)
#1 [internal function]: {%s:%d}()
#2 {main}
