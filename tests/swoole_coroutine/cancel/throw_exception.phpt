--TEST--
swoole_coroutine/cancel: throw exception
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
    $cid = go(function () {
        try {
            while (true) {
                System::sleep(0.1);
                echo "co 2 running\n";
            }
            var_dump('end');
        } catch (Swoole\Coroutine\CanceledException $e) {
            var_dump('cancelled');
        }
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
string(9) "cancelled"
co 1 end
