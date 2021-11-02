--TEST--
swoole_coroutine/join: 6
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
    $cid = go(function () {
        System::sleep(.1);
    });
    $cid_list[] = $cid;
    $cid_list[] = 99999; // not exists
    Assert::true(Coroutine::join($cid_list));
    Assert::false(Coroutine::exists($cid));
    echo "DONE\n";
});
?>
--EXPECT--
DONE
