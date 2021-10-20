--TEST--
swoole_coroutine/cancel: push to channel
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
    $chan = new Coroutine\Channel(1);
    $cid = Coroutine::getCid();
    go(function () use ($cid) {
        System::sleep(0.002);
        Assert::true(Coroutine::cancel($cid));
    });

    Assert::assert($chan->push("hello world [1]", 100));
    Assert::eq(Coroutine::isCanceled(), false);
    Assert::eq($chan->errCode, SWOOLE_CHANNEL_OK);

    Assert::eq($chan->push("hello world [2]", 100), false);
    Assert::eq(Coroutine::isCanceled(), true);
    Assert::eq($chan->errCode, SWOOLE_CHANNEL_CANCELED);

    echo "Done\n";
});

?>
--EXPECT--
Done
