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
    swoole_timer_after(1, [Test::class, 'not_exist']);
}, '/dev/stdout');
fork_exec(function () {
    swoole_timer_after(1, [Test::class, 'foo']);
}, '/dev/stdout');
fork_exec(function () {
    swoole_timer_after(1, [new Test, 'bar']);
}, '/dev/stdout');

?>
--EXPECTF--
Warning: swoole_timer_after() expects parameter 2 to be a valid callback, class 'Test' does not have a method 'not_exist' in %s/tests/swoole_timer/call_private.php on line 12

Warning: swoole_timer_after() expects parameter 2 to be a valid callback, cannot access private method Test::foo() in %s/tests/swoole_timer/call_private.php on line 15

Warning: swoole_timer_after() expects parameter 2 to be a valid callback, cannot access private method Test::bar() in %s/tests/swoole_timer/call_private.php on line 18
