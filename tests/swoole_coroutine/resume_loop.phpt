--TEST--
swoole_coroutine: resume loop
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$cos = [];
for ($n = 500; $n--;) {
    $cos[] = go(function () {
        global $cos;
        Co::yield();
        if (count($cos) > 0) {
            Co::resume(array_shift($cos));
        }
    });
}
Co::resume(array_shift($cos));
echo "DONE\n";
?>
--EXPECT--
DONE
