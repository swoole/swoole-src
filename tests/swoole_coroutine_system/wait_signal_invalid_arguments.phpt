--TEST--
swoole_coroutine_system: waitSignal rejects empty lists and propagates conversion exceptions
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\System;

Coroutine\run(static function () {
    try {
        System::waitSignal([]);
        Assert::true(false, 'An empty signal list must be rejected');
    } catch (ValueError $exception) {
        Assert::contains($exception->getMessage(), 'must not be empty');
    }

    set_error_handler(static function ($severity, $message) {
        throw new ErrorException($message, 0, $severity);
    });
    try {
        foreach ([new stdClass, [SIGUSR1, new stdClass]] as $signals) {
            try {
                System::waitSignal($signals, 0.01);
                Assert::true(false, 'Signal conversion must propagate the error handler exception');
            } catch (ErrorException $exception) {
                Assert::same($exception->getSeverity(), E_WARNING);
            }
            Assert::same(Coroutine::stats()['signal_listener_num'], 0);
        }
    } finally {
        restore_error_handler();
    }

    // A conversion failure must not leave a partial registration behind.
    Assert::true(Swoole\Process::signal(SIGUSR1, static function () {}));
    Assert::true(Swoole\Process::signal(SIGUSR1, null));
    Coroutine::sleep(0.001);
});
echo "DONE\n";
?>
--EXPECT--
DONE
