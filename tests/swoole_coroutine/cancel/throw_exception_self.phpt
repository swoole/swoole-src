--TEST--
swoole_coroutine/cancel: throw exception in current coroutine
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use function Swoole\Coroutine\run;
use Swoole\Coroutine;
use Swoole\Coroutine\CanceledException;

run(function () {
    try {
        Coroutine::cancel(Coroutine::getCid(), true);
        Assert::true(false, 'cancel must throw');
    } catch (CanceledException $e) {
        echo "DONE\n";
    }
});
?>
--EXPECT--
DONE
