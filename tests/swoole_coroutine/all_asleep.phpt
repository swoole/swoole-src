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
--EXPECTREGEX--
===================================================================
 \[FATAL ERROR\]: all coroutines \(count: 2\) are asleep - deadlock!
===================================================================

 \[Coroutine-3\]
--------------------------------------------------------------------
#0  (Swoole\\Coroutine::yield\(\) called at \[[\w\W]*.php:\d+\])|([\w\W]*.php\(\d+\): Swoole\\Coroutine::yield\(\))
#1  (test2\(\) called at \[[\w\W]*:\d+\])|([\w\W]*.php\(\d+\): test2\(\))
(#2 \[internal function\]: \{closure\}\(\))|\n

 \[Coroutine-2\]
--------------------------------------------------------------------
#0  (Swoole\\Coroutine::yield\(\) called at \[[\w\W]*:\d+\])|([\w\W]*.php\(\d+\): Swoole\\Coroutine::yield\(\))
#1  (\{closure\}\(\) called at \[[\w\W]*:\d+\])|([\w\W]*.php\(\d+\): \{closure\}\(\))
#2  (test1\(\) called at \[[\w\W]*:\d+\])|([\w\W]*.php\(\d+\): test1\(\))
(#3 \[internal function\]: \{closure\}\(\))|\n
DONE
