--TEST--
swoole_coroutine: max coro nesting limit
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

function woo(int $current_deep, $target_deep)
{
    $ret = go(function () use ($current_deep, $target_deep) {
        if ($current_deep++ >= $target_deep) {
            return;
        } else {
            woo($current_deep, $target_deep);
        }
    });
    if ($current_deep !== 128 + 1) {
        assert($ret === $current_deep);
    }
}

woo(1, 128 + 1);
?>
--EXPECTF--
[%s]	WARNING	create: reaches the max coroutine nesting level 128
