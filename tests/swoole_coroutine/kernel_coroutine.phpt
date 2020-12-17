--TEST--
swoole_coroutine: kernel coroutine
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const N = 8;

Co\run(function () {
    go(function () {
        for ($i = 0; $i < N / 2; $i++) {
            Co::sleep(0.05);
            echo "php coroutine [$i]\n";
        }
    });
    swoole_test_kernel_coroutine(N, 0.02);
});

?>
--EXPECT--
kernel coroutine [0]
kernel coroutine [1]
php coroutine [0]
kernel coroutine [2]
kernel coroutine [3]
php coroutine [1]
kernel coroutine [4]
kernel coroutine [5]
kernel coroutine [6]
php coroutine [2]
kernel coroutine [7]
php coroutine [3]
