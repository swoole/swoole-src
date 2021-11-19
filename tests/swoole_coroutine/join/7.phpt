--TEST--
swoole_coroutine/join: 7
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
    $cid = go(function () use ($current_cid) {
        System::sleep(.1);
    });
    $cid_list[] = $cid;

    Swoole\Event::defer(function () use ($current_cid) {
        echo "DEFER CALLBACK\n";
        Coroutine::cancel($current_cid);
    });

    Assert::false(Coroutine::join($cid_list));
    Assert::eq(swoole_last_error(), SWOOLE_ERROR_CO_CANCELED);
    Assert::true(Coroutine::exists($cid));
    echo "DONE\n";
});
?>
--EXPECT--
DEFER CALLBACK
DONE
