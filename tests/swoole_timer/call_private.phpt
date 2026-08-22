--TEST--
swoole_timer: call private method
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

class Test
{
    private static function foo() { }

    private function bar() { }
}

// method not exists
//------------------------------------------------------------------------------------------------------------------
$pm = ProcessManager::exec(function () {
    Swoole\Timer::After(1, [Test::class, 'not_exist']);
});
$pm->expectExitCode(255);
$output = $pm->getChildOutput();
    Assert::contains($output, 'Uncaught TypeError: Swoole\Timer::after(): Argument #2 ($callback) must be a valid callback, class Test does not have a method "not_exist"');

// private method
//------------------------------------------------------------------------------------------------------------------
$pm = ProcessManager::exec(function () {
    Swoole\Timer::After(1, [Test::class, 'foo']);
});
$pm->expectExitCode(255);
$output = $pm->getChildOutput();
    Assert::contains($output, 'Swoole\Timer::after(): Argument #2 ($callback) must be a valid callback, cannot access private method Test::foo()');

// private method
//------------------------------------------------------------------------------------------------------------------
$pm = ProcessManager::exec(function () {
    Swoole\Timer::After(1, [new Test, 'bar']);
});
$pm->expectExitCode(255);
$output = $pm->getChildOutput();
    Assert::contains($output, 'Swoole\Timer::after(): Argument #2 ($callback) must be a valid callback, cannot access private method Test::bar()');

?>
--EXPECT--
