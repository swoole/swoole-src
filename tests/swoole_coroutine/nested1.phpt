--TEST--
swoole_coroutine: coro channel
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    echo "co[1] start\n";
    co::sleep(.01);
    go(function () {
        echo "co[2] start\n";
        co::sleep(.01);
        echo "co[2] exit\n";
    });
    echo "co[1] exit\n";
});
echo "end\n";
?>
--EXPECT--
co[1] start
end
co[2] start
co[1] exit
co[2] exit
