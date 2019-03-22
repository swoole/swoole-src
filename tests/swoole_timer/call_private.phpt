--TEST--
swoole_timer: call private method
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_docker('not support');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

class Test
{
    private static function foo() { }

    private function bar() { }
}

fork_exec(function () {
    Swoole\Timer::After(1, [Test::class, 'not_exist']);
}, '/dev/stdout');
fork_exec(function () {
    Swoole\Timer::After(1, [Test::class, 'foo']);
}, '/dev/stdout');
fork_exec(function () {
    Swoole\Timer::After(1, [new Test, 'bar']);
}, '/dev/stdout');

?>
--EXPECTF--
Fatal error: Uncaught TypeError: Argument 2 passed to Swoole\Timer::after() must be callable, array given in %s/tests/swoole_timer/call_private.php:12
Stack trace:
#0 %s/tests/swoole_timer/call_private.php(12): Swoole\Timer::after(1, Array)
#1 %s/tests/include/functions.php(541): {closure}()
#2 %s/tests/swoole_timer/call_private.php(13): fork_exec(Object(Closure), '/dev/stdout')
#3 {main}
  thrown in %s/tests/swoole_timer/call_private.php on line 12

Fatal error: Uncaught TypeError: Argument 2 passed to Swoole\Timer::after() must be callable, array given in %s/tests/swoole_timer/call_private.php:15
Stack trace:
#0 %s/tests/swoole_timer/call_private.php(15): Swoole\Timer::after(1, Array)
#1 %s/tests/include/functions.php(541): {closure}()
#2 %s/tests/swoole_timer/call_private.php(16): fork_exec(Object(Closure), '/dev/stdout')
#3 {main}
  thrown in %s/tests/swoole_timer/call_private.php on line 15

Fatal error: Uncaught TypeError: Argument 2 passed to Swoole\Timer::after() must be callable, array given in %s/tests/swoole_timer/call_private.php:18
Stack trace:
#0 %s/tests/swoole_timer/call_private.php(18): Swoole\Timer::after(1, Array)
#1 %s/tests/include/functions.php(541): {closure}()
#2 %s/tests/swoole_timer/call_private.php(19): fork_exec(Object(Closure), '/dev/stdout')
#3 {main}
  thrown in %s/tests/swoole_timer/call_private.php on line 18
