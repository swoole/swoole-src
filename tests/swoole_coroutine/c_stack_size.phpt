--TEST--
swoole_coroutine: c_stack_size
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const K = 1024;
const M = K * 1024;
const G = M * 1024;

// echo "default 2M\n";
$info = co::stats();
Assert::assert($info['c_stack_size'] == 2 * M);
Assert::assert($info['coroutine_num'] == 0);
Assert::assert($info['coroutine_peak_num'] == 0);

co::set(['c_stack_size' => 1 * M]);
for ($n = 100; $n--;) {
    go(function () { co::sleep(0.001); });
}
// echo "1M\n";
$info = co::stats();
Assert::assert($info['c_stack_size'] == M);
Assert::assert($info['coroutine_num'] == 100);
Assert::assert($info['coroutine_peak_num'] == 100);

co::set(['c_stack_size' => 1 * K]); // will be extend
for ($n = 100; $n--;) {
    go(function () { co::sleep(0.001); });
}
// echo "256K\n";
$info = co::stats();
Assert::assert($info['c_stack_size'] == 64 * K);
Assert::assert($info['coroutine_num'] == 200);
Assert::assert($info['coroutine_peak_num'] == 200);

co::set(['c_stack_size' => 511 * K]); // will be aligned
for ($n = 100; $n--;) {
    go(function () { co::sleep(0.001); });
}
// echo "512K\n";
$info = co::stats();
Assert::assert($info['c_stack_size'] == 512 * K);
Assert::assert($info['coroutine_num'] == 300);
Assert::assert($info['coroutine_peak_num'] == 300);

co::set(['c_stack_size' => 1 * G]); // will be limit
for ($n = 100; $n--;) {
    go(function () { co::sleep(0.001); });
}
// echo "16M\n";
$info = co::stats();
Assert::assert($info['c_stack_size'] == 16 * M);
Assert::assert($info['coroutine_num'] == 400);
Assert::assert($info['coroutine_peak_num'] == 400);

co::set(['c_stack_size' => -1]); // will be limit
for ($n = 100; $n--;) {
    go(function () { co::sleep(0.001); });
}
// echo "16M\n";
$info = co::stats();
Assert::assert($info['c_stack_size'] == 16 * M);
Assert::assert($info['coroutine_num'] == 500);
Assert::assert($info['coroutine_peak_num'] == 500);
?>
DONE
--EXPECTF--
DONE
