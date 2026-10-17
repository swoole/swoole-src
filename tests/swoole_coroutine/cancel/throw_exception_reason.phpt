--TEST--
swoole_coroutine/cancel: attach a reason
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\CanceledException;
use Swoole\Coroutine\System;

Coroutine\run(function () {
    try {
        Coroutine::cancel(Coroutine::getCid(), false, 'unused');
    } catch (ValueError $e) {
        echo $e->getMessage(), "\n";
    }

    $reason = new RuntimeException('job timed out');
    $cid = Coroutine::create(function () use ($reason) {
        try {
            System::sleep(1);
        } catch (CanceledException $e) {
            Assert::same($e->getReason(), $reason);
            Assert::null($e->getPrevious());
            echo $e->getReason()::class, ': ', $e->getReason()->getMessage(), "\n";
        }
    });

    System::sleep(0.01);
    Coroutine::cancel($cid, true, $reason);

    $reason = ['type' => 'self cancel'];
    try {
        Coroutine::cancel(Coroutine::getCid(), true, $reason);
    } catch (CanceledException $e) {
        Assert::same($e->getReason(), $reason);
        echo $e->getReason()['type'], "\n";
    }
});
?>
--EXPECT--
Swoole\Coroutine::cancel(): Argument #3 ($reason) must be null when argument #2 ($throw_exception) is false
RuntimeException: job timed out
self cancel
