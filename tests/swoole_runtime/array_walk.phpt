--TEST--
swoole_runtime: array_walk
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();
for ($n = 2; $n--;) {
    go(function () {
        $array = range(0, 1);
        array_walk($array, function ($item) {
            Co::sleep([0.01, 0.001][$item]);
        });
    });
}
swoole_event_wait();
?>
--EXPECTF--
