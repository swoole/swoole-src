--TEST--
swoole_coroutine: fatal error
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Co::set([
    'enable_deadlock_check' => true,
]);


Co\run(function () {
    test_not_found();
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
