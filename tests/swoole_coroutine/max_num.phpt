--TEST--
swoole_coroutine: cid map max num
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
const MAX_N = 1000;
co::set([
    'max_coroutine' => MAX_N
]);
for ($c = MAX_N + 1; $c--;) {
    $ret = go(function () {
        co::sleep(0.001);
    });
}
$info = co::stats();
Assert::same($info['c_stack_size'], 2097152);
Assert::same($info['coroutine_num'], MAX_N);
Assert::same($info['coroutine_peak_num'], MAX_N);
?>
--EXPECTF--
Warning: go(): exceed max number of coroutine %d in %s/tests/swoole_coroutine/max_num.php on line %d
