--TEST--
swoole_timer: call private method
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

class Test
{
    private static function foo() { }

    private function bar() { }
}

swoole_fork_exec(function () {
    Swoole\Timer::After(1, [Test::class, 'not_exist']);
});
swoole_fork_exec(function () {
    Swoole\Timer::After(1, [Test::class, 'foo']);
});
swoole_fork_exec(function () {
    Swoole\Timer::After(1, [new Test, 'bar']);
});

?>
--EXPECTF--
Fatal error: Uncaught TypeError: Argument 2 passed to Swoole\Timer::after() must be callable, array given in %s/tests/swoole_timer/call_private.php:%d
Stack trace:
#0 %s/tests/swoole_timer/call_private.php(%d): Swoole\Timer::after(1, Array)
#1 [internal function]: {closure}(Object(Swoole\Process))
#2 %s/tests/include/functions.php(%d): Swoole\Process->start()
#3 %s/tests/swoole_timer/call_private.php(%d): swoole_fork_exec(Object(Closure))
#4 {main}
  thrown in %s/tests/swoole_timer/call_private.php on line %d

Fatal error: Uncaught TypeError: Argument 2 passed to Swoole\Timer::after() must be callable, array given in %s/tests/swoole_timer/call_private.php:%d
Stack trace:
#0 %s/tests/swoole_timer/call_private.php(%d): Swoole\Timer::after(1, Array)
#1 [internal function]: {closure}(Object(Swoole\Process))
#2 %s/tests/include/functions.php(%d): Swoole\Process->start()
#3 %s/tests/swoole_timer/call_private.php(%d): swoole_fork_exec(Object(Closure))
#4 {main}
  thrown in %s/tests/swoole_timer/call_private.php on line %d

Fatal error: Uncaught TypeError: Argument 2 passed to Swoole\Timer::after() must be callable, array given in %s/tests/swoole_timer/call_private.php:%d
Stack trace:
#0 %s/tests/swoole_timer/call_private.php(%d): Swoole\Timer::after(1, Array)
#1 [internal function]: {closure}(Object(Swoole\Process))
#2 %s/tests/include/functions.php(%d): Swoole\Process->start()
#3 %s/tests/swoole_timer/call_private.php(%d): swoole_fork_exec(Object(Closure))
#4 {main}
  thrown in %s/tests/swoole_timer/call_private.php on line %d
