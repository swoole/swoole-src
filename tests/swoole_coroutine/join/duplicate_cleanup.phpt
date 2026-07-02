--TEST--
swoole_coroutine/join: duplicate cid cleanup
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use function Swoole\Coroutine\go;
use function Swoole\Coroutine\run;

run(function () {
    $cid = go(function () {
        Coroutine::sleep(0.01);
    });

    Assert::false(Coroutine::join([$cid, $cid], 0.001));
    Assert::eq(swoole_last_error(), SWOOLE_ERROR_WRONG_OPERATION);
    Assert::true(Coroutine::join([$cid], 1));
    echo "Done\n";
});
?>
--EXPECT--
Done
