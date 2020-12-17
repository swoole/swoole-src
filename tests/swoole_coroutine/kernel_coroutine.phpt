--TEST--
swoole_coroutine: kernel coroutine
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const N = 4;
const T = 0.02;

Co\run(function () {
    go(function () {
        for ($i = 0; $i < N; $i++) {
            Co::sleep(T);
        }
    });
    swoole_test_kernel_coroutine(N, T);
});
Assert::eq(Co::stats()['coroutine_peak_num'], 3);
echo "Done\n";

?>
--EXPECT--
Done
