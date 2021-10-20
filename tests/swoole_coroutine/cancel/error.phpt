--TEST--
swoole_coroutine/cancel: error
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
    Assert::false(Coroutine::cancel(Coroutine::getCid()));
    Assert::eq(swoole_last_error(), SWOOLE_ERROR_CO_CANNOT_CANCEL);
    
    Assert::false(Coroutine::cancel(999));
    Assert::eq(swoole_last_error(), SWOOLE_ERROR_CO_NOT_EXISTS);
});

?>
--EXPECT--
