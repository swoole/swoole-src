--TEST--
swoole_coroutine: create coroutine after RSHTUDOWN
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
register_shutdown_function(function () {
    go(function () {
        co::sleep(.01);
        echo "DONE\n";
    });
    swoole_event::wait();
});
exit(0);

?>
--EXPECTF--
DONE
