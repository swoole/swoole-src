--TEST--
swoole_coroutine: c_stack_size
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
// echo "default 2M\n";
$info = co::stats();
Assert::eq($info['c_stack_size'], 2097152);
Assert::eq($info['coroutine_num'], 0);
Assert::eq($info['coroutine_peak_num'], 0);

co::set(['c_stack_size' => 1024 * 1024]);
for ($n = 100; $n--;) {
    go(function () { co::sleep(0.001); });
}
// echo "1M\n";
$info = co::stats();
Assert::eq($info['c_stack_size'], 1024 * 1024);
Assert::eq($info['coroutine_num'], 100);
Assert::eq($info['coroutine_peak_num'], 100);

co::set(['c_stack_size' => 1]); // will be aligned
for ($n = 100; $n--;) {
    go(function () { co::sleep(0.001); });
}
// echo "4K\n";
$info = co::stats();
Assert::eq($info['c_stack_size'], 4096);
Assert::eq($info['coroutine_num'], 200);
Assert::eq($info['coroutine_peak_num'], 200);

co::set(['c_stack_size' => 1024 * 1024 * 1024]); // will be limit
for ($n = 100; $n--;) {
    go(function () { co::sleep(0.001); });
}
// echo "16M\n";
$info = co::stats();
Assert::eq($info['c_stack_size'], 16 * 1024 * 1024);
Assert::eq($info['coroutine_num'], 300);
Assert::eq($info['coroutine_peak_num'], 300);

co::set(['c_stack_size' => -1]); // will be limit
for ($n = 100; $n--;) {
    go(function () { co::sleep(0.001); });
}
// echo "16M\n";
$info = co::stats();
Assert::eq($info['c_stack_size'], 16 * 1024 * 1024);
Assert::eq($info['coroutine_num'], 400);
Assert::eq($info['coroutine_peak_num'], 400);
?>
--EXPECTF--

