--TEST--
swoole_coroutine: getPcid
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

var_dump(Co::getPcid());
go(function () {
    var_dump(Co::getPcid());
    go(function () {
        var_dump(Co::getPcid());
        go(function () {
            var_dump(Co::getPcid());
            go(function () {
                var_dump(Co::getPcid());
            });
            go(function () {
                var_dump(Co::getPcid());
            });
            go(function () {
                var_dump(Co::getPcid());
            });
        });
        var_dump(Co::getPcid());
    });
    var_dump(Co::getPcid());
});
var_dump(Co::getPcid());
?>
--EXPECT--
bool(false)
int(-1)
int(1)
int(2)
int(3)
int(3)
int(3)
int(1)
int(-1)
bool(false)
