--TEST--
swoole_coroutine/cancel: attach a previous exception
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
        Coroutine::cancel(Coroutine::getCid(), false, new RuntimeException('unused'));
    } catch (ValueError $e) {
        echo $e->getMessage(), "\n";
    }

    $cid = Coroutine::create(function () {
        try {
            System::sleep(1);
        } catch (CanceledException $e) {
            echo $e->getPrevious()::class, ': ', $e->getPrevious()->getMessage(), "\n";
        }
    });

    System::sleep(0.01);
    Coroutine::cancel($cid, true, new RuntimeException('job timed out'));

    try {
        Coroutine::cancel(Coroutine::getCid(), true, new LogicException('self cancel'));
    } catch (CanceledException $e) {
        echo $e->getPrevious()::class, ': ', $e->getPrevious()->getMessage(), "\n";
    }
});
?>
--EXPECT--
Swoole\Coroutine::cancel(): Argument #3 ($previous) must be null when argument #2 ($throw_exception) is false
RuntimeException: job timed out
LogicException: self cancel
