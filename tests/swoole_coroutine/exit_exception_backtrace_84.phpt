--TEST--
swoole_coroutine: exit exception backtrace
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_php_version_lower_than('8.4');
?>
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
Fatal error: Uncaught Swoole\ExitException: swoole exit in %s:%d
Stack trace:
#0 %s(%d): exit()
#1 %s(%d): char(%d)
#2 %s(%d): bar('%s')
#3 %s(%d): foo()
#4 [internal function]: {closure:%s:%d}()
#5 {main}
  thrown in %s on line %d

