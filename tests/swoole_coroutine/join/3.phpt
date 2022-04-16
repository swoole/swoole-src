--TEST--
swoole_coroutine/join: 3
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;
use Swoole\Coroutine;
use Swoole\Coroutine\System;

ini_set('swoole.display_errors', 'off');

run(function () {
    $current_cid = Coroutine::getCid();
    $cid_list = [];
    Assert::false(Coroutine::join($cid_list));
    Assert::eq(swoole_last_error(), SWOOLE_ERROR_INVALID_PARAMS);

    Assert::false(Coroutine::join([$current_cid]));
    Assert::eq(swoole_last_error(), SWOOLE_ERROR_WRONG_OPERATION);

    Assert::false(Coroutine::join([9999]));
    Assert::eq(swoole_last_error(), SWOOLE_ERROR_INVALID_PARAMS);

    $cid_list = [];
    $cid_list[] = go(function () {
        System::sleep(.5);
    });
    Assert::false(Coroutine::join($cid_list, 0.01));
    Assert::eq(swoole_last_error(), SWOOLE_ERROR_CO_TIMEDOUT);

    $cid_list = [];
    $cid_list[] = go(function () {
        System::sleep(.5);
    });

    go(function () use($current_cid) {
        System::sleep(.001);
        Coroutine::cancel($current_cid);
    });

    Assert::false(Coroutine::join($cid_list));
    Assert::eq(swoole_last_error(), SWOOLE_ERROR_CO_CANCELED);
});
?>
--EXPECT--
