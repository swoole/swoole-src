--TEST--
swoole_coroutine_wait_group: sleep
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Coroutine\Run(function () {
    $wg = new Swoole\Coroutine\WaitGroup();
    $wg->add(2);
    go(function () use ($wg) {
        Swoole\Coroutine\System::sleep(0.005);
        var_dump(Swoole\Coroutine::getCid());
        $wg->done();
    });
    go(function () use ($wg) {
        Swoole\Coroutine\System::sleep(0.005);
        var_dump(Swoole\Coroutine::getCid());
        $wg->done();
    });
    var_dump(Swoole\Coroutine::getCid());
    $wg->wait();
    echo "DONE\n";
});
?>
--EXPECT--
int(1)
int(2)
int(3)
DONE