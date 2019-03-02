--TEST--
swoole_coroutine: cid map max num
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
co::set([
    'max_coroutine' => SWOOLE_DEFAULT_MAX_CORO_NUM
]);
for ($c = SWOOLE_DEFAULT_MAX_CORO_NUM + 1; $c--;) {
    $ret = go(function () {
        co::sleep(0.001);
    });
}
$info = co::stats();
Assert::eq($info['c_stack_size'], 2097152);
Assert::eq($info['coroutine_num'], 3000);
Assert::eq($info['coroutine_peak_num'], 3000);
?>
--EXPECTF--
Warning: go(): exceed max number of coroutine 3000. in %s/tests/swoole_coroutine/max_num.php on line 9
