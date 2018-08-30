--TEST--
swoole_coroutine: exit
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
go(function () {
    co::sleep(0.001);
    echo "in coroutine";
    exit;
});
?>
--EXPECTF--
in coroutine
Fatal error: Uncaught Error: cannot exit in coroutine. in %s:%d
Stack trace:
#0 {main}
  thrown in %s on line %d