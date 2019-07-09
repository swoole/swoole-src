--TEST--
swoole_coroutine: getPcid by random cid
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

echo Co::getPcid(-1), "\n";
echo Co::getPcid(0), "\n";
go(function () {
    echo Co::getPcid(0), "\n";
    echo Co::getPcid(1), "\n";
    echo Co::getPcid(2), "\n";
    go(function () {
        echo Co::getPcid(0), "\n";
        echo Co::getPcid(1), "\n";
        go(function () {
            echo Co::getPcid(0), "\n";
            echo Co::getPcid(1), "\n";
            echo Co::getPcid(2), "\n";
            echo Co::getPcid(3), "\n";
            echo Co::getPcid(4), "\n";
        });
        echo Co::getPcid(2), "\n";
        echo Co::getPcid(3), "\n";
    });
    echo Co::getPcid(), "\n";
});
echo Co::getPcid(), "\n";
?>
--EXPECT--
-1
-1
-1
-1
-1
1
-1
2
-1
1
2
-1
1
-1
-1
-1