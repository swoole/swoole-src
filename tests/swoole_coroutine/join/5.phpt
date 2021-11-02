--TEST--
swoole_coroutine/join: 5
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
    $cid_list[] = go(function () {
        System::sleep(.1);
    });
    // concurrency join
    swoole_event_defer(function () use ($cid_list) {
        go(function () use ($cid_list) {
            Assert::false(Coroutine::join($cid_list));
            Assert::eq(swoole_last_error(), SWOOLE_ERROR_CO_HAS_BEEN_BOUND);
            echo "DONE 2\n";
        });
    });
    Assert::true(Coroutine::join($cid_list));
    echo "DONE 1\n";
});
?>
--EXPECT--
DONE 2
DONE 1
