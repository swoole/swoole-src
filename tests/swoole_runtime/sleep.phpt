--TEST--
swoole_runtime: sleep
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
go(function () {
    // sleep
    $s = microtime(true);
    Assert::eq(sleep(1), 0);
    time_approximate(1, microtime(true) - $s);
    Assert::eq(sleep(0), 0);
    Assert::false(sleep(-1), -1);

    // usleep
    $s = microtime(true);
    $t = ms_random(0.01, 0.1);
    usleep($t * 1000 * 1000);
    time_approximate($t, microtime(true) - $s);
    usleep(0);
    usleep(-1);

    // time_nanosleep
    Assert::false(time_nanosleep(-1, 1));
    Assert::true(time_nanosleep(0, 1));
    Assert::true(time_nanosleep(0, 1000 * 1000));

    // time_sleep_until
    $s = microtime(true);
    Assert::true(time_sleep_until($s + 1));
    time_approximate(1, microtime(true) - $s);
    Assert::false(time_sleep_until($s));
});
echo "NON-BLOCKED\n";
Swoole\Event::wait();
echo "\nDONE\n";
?>
--EXPECTF--
NON-BLOCKED

Warning: sleep(): Number of seconds must be greater than or equal to 0 in %s on line %d

Warning: usleep(): Number of seconds must be greater than or equal to 0 in %s on line %d

Warning: time_nanosleep(): The seconds value must be greater than 0 in %s on line %d

Warning: time_sleep_until(): Sleep until to time is less than current time in %s on line %d

DONE
