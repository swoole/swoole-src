--TEST--
swoole_lock: constructor parses before native state
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Lock;

$lock = (new ReflectionClass(Lock::class))->newInstanceWithoutConstructor();
$reentered = false;
set_error_handler(function () use ($lock, &$reentered): bool {
    $reentered = true;
    $lock->__construct(SWOOLE_MUTEX);

    return true;
});
try {
    try {
        $lock->__construct(3.5);
        Assert::true(false);
    } catch (Error $error) {
        Assert::contains($error->getMessage(), 'Constructor of Swoole\Lock can only be called once');
    }
} finally {
    restore_error_handler();
}

Assert::true($reentered);
Assert::true($lock->lock());
Assert::true($lock->unlock());
?>
--EXPECT--
