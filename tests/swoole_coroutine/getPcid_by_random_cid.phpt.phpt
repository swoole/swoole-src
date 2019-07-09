--TEST--
swoole_coroutine: getPcid by random cid
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

var_dump(Co::getPcid(-1)); // -1
var_dump(Co::getPcid(0)); // -1
go(function () {
    var_dump(Co::getPcid(0)); // -1
    var_dump(Co::getPcid(1)); // -1
    var_dump(Co::getPcid(2)); // false
    go(function () {
        var_dump(Co::getPcid(0)); // 1
        var_dump(Co::getPcid(1)); // -1
        go(function () {
            var_dump(Co::getPcid(0)); // 2
            var_dump(Co::getPcid(1)); // -1
            var_dump(Co::getPcid(2)); // 1
            var_dump(Co::getPcid(3)); // 2
            var_dump(Co::getPcid(4)); // false
        });
        var_dump(Co::getPcid(2)); // 1
        var_dump(Co::getPcid(3)); // false
    });
});
?>
--EXPECT--
int(-1)
int(-1)
int(-1)
int(-1)
bool(false)
int(1)
int(-1)
int(2)
int(-1)
int(1)
int(2)
bool(false)
int(1)
bool(false)