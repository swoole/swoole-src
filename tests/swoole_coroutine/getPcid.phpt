--TEST--
swoole_coroutine: getPcid
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
echo Co::getPcid(), "\n";
go(function () {
    echo Co::getPcid(), "\n";
    go(function () {
        echo Co::getPcid(), "\n";
        go(function () {
            echo Co::getPcid(), "\n";
            go(function () {
                echo Co::getPcid(), "\n";
            });
            go(function () {
                echo Co::getPcid(), "\n";
            });
            go(function () {
                echo Co::getPcid(), "\n";
            });
        });
        echo Co::getPcid(), "\n";
    });
    echo Co::getPcid(), "\n";
});
echo Co::getPcid(), "\n";
?>
--EXPECT--
-1
-1
1
2
3
3
3
1
-1
-1
