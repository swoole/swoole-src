--TEST--
swoole_coroutine_lock: constructor parses before native state
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Lock;
use function Swoole\Coroutine\run;

$lock = (new ReflectionClass(Lock::class))->newInstanceWithoutConstructor();
$reentered = false;
set_error_handler(function () use ($lock, &$reentered): bool {
    $reentered = true;
    $lock->__construct(false);

    return true;
});
try {
    try {
        $lock->__construct(null);
        Assert::true(false);
    } catch (Error $error) {
        Assert::contains($error->getMessage(), 'Constructor of Swoole\Coroutine\Lock can only be called once');
    }
} finally {
    restore_error_handler();
}

Assert::true($reentered);
run(function () use ($lock): void {
    Assert::true($lock->lock());
    Assert::true($lock->unlock());
});
?>
--EXPECT--
