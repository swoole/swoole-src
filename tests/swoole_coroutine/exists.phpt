--TEST--
swoole_coroutine: exists
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    go(function () {
        go(function () {
            Co::sleep(0.001);
            var_dump(Co::exists(Co::getPcid())); // 1: true
        });
        go(function () {
            Co::sleep(0.003);
            var_dump(Co::exists(Co::getPcid())); // 3: false
        });
        Co::sleep(0.002);
        var_dump(Co::exists(Co::getPcid())); // 2: false
    });
});
?>
--EXPECT--
bool(true)
bool(false)
bool(false)
