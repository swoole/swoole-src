--TEST--
swoole_coroutine: create coroutine after RSHTUDOWN
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
register_shutdown_function(function () {
    go(function () {
        co::sleep(1);
    });
});
exit(0);

?>
--EXPECTF--
Fatal error: go(): can not use coroutine after php_request_shutdown in %s on line %d