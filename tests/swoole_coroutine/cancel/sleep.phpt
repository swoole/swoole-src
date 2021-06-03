--TEST--
swoole_coroutine/cancel: sleep
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
    $cid = Coroutine::getCid();
    go(function () use ($cid) {
        System::sleep(0.002);
        Assert::true(Coroutine::cancel($cid));
        Assert::false(Coroutine::isCanceled());
    });
    $retval = System::sleep(10000);
    echo "Done\n";
    Assert::eq($retval, false);
    Assert::assert(Coroutine::isCanceled());
    Assert::eq(swoole_last_error(), SWOOLE_ERROR_CO_CANCELED);
});

?>
--EXPECT--
Done
