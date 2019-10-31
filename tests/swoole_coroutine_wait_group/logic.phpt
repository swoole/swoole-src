--TEST--
swoole_coroutine_wait_group: logic
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Swoole\Coroutine\Run(function () {
    $wg = new Swoole\Coroutine\WaitGroup;
    Assert::throws(function () use ($wg) {
        $wg->add(-1);
    }, LogicException::class);
    echo "DONE\n";
});
?>
--EXPECT--
DONE
