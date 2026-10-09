--TEST--
swoole_timer: clear the PHP timers after a memory limit fatal error with many sleeping coroutines
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_valgrind('the memory limit needs the Zend allocator');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

ini_set('memory_limit', '64M');

Co\run(function () {
    // never fires and only has to be pending when the request shuts down
    Swoole\Timer::after(600000, function () {});
    // every sleeping coroutine holds a timer too
    while (true) {
        go(function () {
            Co::sleep(600);
        });
    }
});
?>
--EXPECTF--
Fatal error: Allowed memory size of %d bytes exhausted %s
