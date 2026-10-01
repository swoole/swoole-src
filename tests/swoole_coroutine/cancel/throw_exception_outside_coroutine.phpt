--TEST--
swoole_coroutine/cancel: reject throwing cancellation outside a coroutine
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;

Assert::eq(Coroutine::getCid(), -1);
Assert::false(Coroutine::cancel(Coroutine::getCid(), true));
Assert::eq(swoole_last_error(), SWOOLE_ERROR_CO_NOT_EXISTS);
?>
--EXPECT--
