--TEST--
swoole_coroutine: coro parallel1
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    echo "co[1] start\n";
    co::sleep(.01);
    echo "co[1] exit\n";
});

go(function () {
    echo "co[2] start\n";
    co::sleep(.02);
    echo "co[2] exit\n";
});
echo "end\n";
Swoole\Event::wait();
?>
--EXPECT--
co[1] start
co[2] start
end
co[1] exit
co[2] exit
