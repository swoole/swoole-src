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
    try {
        sleep(-1);
    } catch (Throwable $e) {
        Assert::contains($e->getMessage(), 'must be greater than or equal to 0');
    }

    // usleep
    $s = microtime(true);
    $t = ms_random(0.01, 0.1);
    usleep($t * 1000 * 1000);
    time_approximate($t, microtime(true) - $s);
    usleep(0);
    try {
         usleep(-1);
    } catch (Throwable $e) {
        Assert::contains($e->getMessage(), 'must be greater than or equal to 0');
    }

    // time_nanosleep
    try {
        time_nanosleep(-1, 1);
    } catch (Throwable $e) {
        Assert::contains($e->getMessage(), 'must be greater than or equal to 0');
    }

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

Warning: time_sleep_until(): Argument #1 ($timestamp) must be greater than or equal to the current time in %s on line %d

DONE
