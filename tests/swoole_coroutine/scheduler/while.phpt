--TEST--
swoole_coroutine/scheduler: while with opcache enable
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_constant_not_defined('SWOOLE_CORO_SCHEDULER');
skip_if_ini_bool_equal_to('opcache.enable_cli', false);
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$default = 10;
$max_msec = 10;
Co::set(['enable_preemptive_scheduler' => 1]);

$start = microtime(1);
echo "start\n";
$flag = 1;

go(function () use (&$flag, $max_msec) {
    echo "coro 1 start to loop\n";
    $i = 0;
    while ($flag) {
        $i++;
    }
    echo "coro 1 can exit\n";
});

$end = microtime(1);
$msec = ($end - $start) * 1000;
USE_VALGRIND || Assert::lessThanEq(abs($msec - $max_msec), $default);

go(function () use (&$flag) {
    echo "coro 2 set flag = false\n";
    $flag = false;
});
echo "end\n";
?>
--EXPECTF--
start
coro 1 start to loop
coro 2 set flag = false
end
coro 1 can exit
