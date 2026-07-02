--TEST--
swoole_runtime: time_nanosleep invalid nanoseconds
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_SLEEP);

try {
    time_nanosleep(0, 1000000000);
} catch (ValueError $e) {
    echo $e->getMessage(), "\n";
}

Co\run(function () {
    try {
        time_nanosleep(0, 1000000000);
    } catch (ValueError $e) {
        echo $e->getMessage(), "\n";
    }
});
?>
--EXPECT--
Nanoseconds was not in the range 0 to 999 999 999 or seconds was negative
Nanoseconds was not in the range 0 to 999 999 999 or seconds was negative
