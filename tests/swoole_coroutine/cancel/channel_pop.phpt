--TEST--
swoole_coroutine/cancel: pop from channel
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;
use Swoole\Coroutine;
use Swoole\Coroutine\System;

run(function () {
    $chan = new Coroutine\Channel(4);
    $cid = Coroutine::getCid();
    go(function () use ($cid) {
        System::sleep(0.002);
        Assert::true(Coroutine::cancel($cid));
    });
    Assert::eq($chan->pop(100), false);
    Assert::assert(Coroutine::isCanceled());
    Assert::eq($chan->errCode, SWOOLE_CHANNEL_CANCELED);
    echo "Done\n";
});

?>
--EXPECT--
Done
