--TEST--
swoole_coroutine_system: register a signal wait before the waiting coroutine yields
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_class_not_exist(Swoole\Process::class);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\System;
use Swoole\Process;

Coroutine\run(static function (): void {
    // The signal arrives as soon as the waiting coroutine yields
    $cid = Coroutine::create(static function (): void {
        Assert::same(System::waitSignal(SIGUSR1, 1), SIGUSR1);
    });
    Process::kill(getmypid(), SIGUSR1);
    Assert::true(Coroutine::join([$cid], 1));

    // A wait cancelled straight away leaves no registration behind
    $cid = Coroutine::create(static function (): void {
        Assert::false(System::waitSignal(SIGUSR1));
        Assert::same(swoole_last_error(), SWOOLE_ERROR_CO_CANCELED);
    });
    Assert::true(Coroutine::cancel($cid));
    Coroutine::sleep(0.01);
    Assert::true(Process::signal(SIGUSR1, static function (): void {}));
    Assert::true(Process::signal(SIGUSR1, null));
});

echo "DONE\n";
?>
--EXPECT--
DONE
