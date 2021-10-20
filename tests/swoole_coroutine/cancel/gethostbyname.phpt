--TEST--
swoole_coroutine/cancel: gethostbyname
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;
use Swoole\Coroutine;
use Swoole\Event;
use Swoole\Coroutine\System;

run(function () {
    $cid = Coroutine::getCid();
    Event::defer(function () use ($cid) {
        Assert::true(Coroutine::cancel($cid));
    });
    $retval = System::gethostbyname('www.baidu.com');
    echo "Done\n";
    Assert::eq($retval, false);
    Assert::eq(swoole_last_error(), SWOOLE_ERROR_CO_CANCELED);
});

?>
--EXPECT--
Done
