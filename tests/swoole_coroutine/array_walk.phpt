--TEST--
swoole_coroutine: array_walk
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Co\run(function () {
    for ($n = 2; $n--;) {
        go(function () {
            $array = range(0, 1);
            array_walk($array, function ($item) {
                Co::sleep([0.01, 0.001][$item]);
            });
        });
    }
});
echo "DONE\n";
?>
--EXPECTF--
DONE
