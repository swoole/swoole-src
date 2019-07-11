--TEST--
swoole_coroutine: exit exception backtrace
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
function foo()
{
    bar(get_safe_random());
}

function bar(string $random)
{
    char(mt_rand(0, PHP_INT_MAX));
}

function char(int $random)
{
    exit;
}

go(function () {
    co::sleep(0.001);
});
go(function () {
    foo();
});
?>
--EXPECTF--
Fatal error: Uncaught Swoole\ExitException: swoole exit in %s/tests/swoole_coroutine/exit_exception_backtrace.php:15
Stack trace:
#0 %s/tests/swoole_coroutine/exit_exception_backtrace.php(10): char(%d)
#1 %s/tests/swoole_coroutine/exit_exception_backtrace.php(5): bar('%s...')
#2 %s/tests/swoole_coroutine/exit_exception_backtrace.php(22): foo()
#3 {main}
  thrown in %s/tests/swoole_coroutine/exit_exception_backtrace.php on line 15
