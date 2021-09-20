--TEST--
swoole_coroutine/join: 2
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;
use Swoole\Coroutine;
use Swoole\Coroutine\System;

const N = 10;

run(function () {
    $cid_list = [];
    $result = 0;

    $s = microtime(true);
    for ($i = 0; $i < N; $i++) {
        $cid_list[] = go(function () use ($i, &$result) {
            System::sleep(.3);
            $result++;
        });
    }

    Assert::true(Coroutine::join($cid_list));
    Assert::assert(approximate(0.3, microtime(true) - $s));
    Assert::eq($result, N);
    echo "ALL DONE\n";
});
?>
--EXPECT--
ALL DONE
