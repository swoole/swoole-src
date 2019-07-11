--TEST--
swoole_coroutine: cid increment
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
for ($n = 0; $n < MAX_LOOPS; $n++) {
    go(function () use ($n) {
        Assert::same(co::getCid(), $n + 1);
    });
}
echo "DONE\n";
?>
--EXPECT--
DONE
