--TEST--
swoole_coroutine: set timeout with fractional seconds
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\TimeoutException;
use function Swoole\Coroutine\go;
use function Swoole\Coroutine\run;

run(function () {
    go(function () {
        try {
            Assert::true(Coroutine::setTimeLimit(1.5));
            Coroutine::sleep(1.2);
            echo "completed\n";
        } catch (TimeoutException $e) {
            echo "unexpected timeout\n";
        }
    });

    go(function () {
        try {
            Assert::true(Coroutine::setTimeLimit(0.5));
            Coroutine::sleep(2);
        } catch (TimeoutException $e) {
            echo "timeout\n";
        }
    });
});
?>
--EXPECT--
timeout
completed
