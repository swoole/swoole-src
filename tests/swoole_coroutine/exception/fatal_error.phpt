--TEST--
swoole_coroutine/exception: fatal error
--SKIPIF--
<?php require  __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Co\run(function () {
    call_func_not_exists();
    sleep(1);
    echo "error\n";
});
?>
--EXPECTF--
Fatal error: Uncaught Error: Call to undefined function call_func_not_exists() in %s:%d
Stack trace:
#0 {main}
  thrown in %s on line %d
