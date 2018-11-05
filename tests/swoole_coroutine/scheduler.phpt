--TEST--
swoole_coroutine: coroutine scheduler
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$co1 = go(function () {
    co::yield();
    echo "co1\n";
    go(function () {
        co::yield();
        echo "co4\n";
    });
});

go(function () use ($co1) {
    go(function () {
        co::sleep(.001);
        echo "co3\n";
        co::resume(4);
    });
    co::resume($co1);
    echo "co2\n";
});

?>
--EXPECT--
co1
co2
co3
co4
