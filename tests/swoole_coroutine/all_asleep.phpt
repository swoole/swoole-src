--TEST--
swoole_coroutine: all asleep
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Co::set([
    'enable_deadlock_check' => true,
]);

function test1()
{
    $f = function () {
        Co::yield();
    };
    $f();
}

function test2()
{
    Co::yield();
}

Co\run(function () {
    go(function () {
        test1();
    });
    go(function () {
        test2();
    });
    Co::sleep(0.1);
});
echo "DONE\n";
?>
--EXPECTF--
===================================================================
 [FATAL ERROR]: all coroutines (count: 2) are asleep - deadlock!
===================================================================

 [Coroutine-3]
--------------------------------------------------------------------
#0  Swoole\Coroutine::yield() called at [%s:%d]
#1  test2() called at [%s:%d]


 [Coroutine-2]
--------------------------------------------------------------------
#0  Swoole\Coroutine::yield() called at [%s:%d]
#1  {closure}() called at [%s:%d]
#2  test1() called at [%s:%d]

DONE
