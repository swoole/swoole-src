--TEST--
swoole_coroutine/cancel: kill
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
skip("experimental");
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;
use Swoole\Coroutine;
use Swoole\Coroutine\System;

run(function () {
    $cid = go(function () {
        while (true) {
            System::sleep(0.1);
            echo "co 2 running\n";
        }
        var_dump('end');
    });

    System::sleep(0.3);
    Co::cancel($cid, true);

    System::sleep(0.2);
    echo "co 1 end\n";
});
?>
--EXPECT--
co 2 running
co 2 running
co 1 end
