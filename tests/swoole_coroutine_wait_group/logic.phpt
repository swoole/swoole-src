--TEST--
swoole_coroutine_wait_group: logic
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $wg = new Swoole\Coroutine\WaitGroup;
    Assert::throws(function () use ($wg) {
        $wg->add(-1);
    }, LogicException::class);
    $wg->add(1);
    go(function () use ($wg) {
        Co::sleep(0.001);
        Assert::throws(function () use ($wg) {
            $wg->add(1);
        }, LogicException::class);
        $wg->done();
    });
    $wg->wait();
    Assert::throws(function () use ($wg) {
        $wg->done();
    }, LogicException::class);
    echo "DONE\n";
});
?>
--EXPECT--
DONE
