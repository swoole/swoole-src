--TEST--
swoole_runtime: sleep
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
go(function () {
    sleep(0);
    sleep(-1);
    usleep(1000);
    time_nanosleep(-1, 1);
    time_nanosleep(0, 1);
    time_nanosleep(0, 1000 * 1000);
    echo "\nDONE\n";
});
?>
--EXPECTF--
Warning: sleep(): Number of seconds must be greater than or equal to 0 in %s on line %d

Warning: time_nanosleep(): The seconds value must be greater than 0 in %s on line %d

DONE
