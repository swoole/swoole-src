--TEST--
swoole_process: constructor parses before native state
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;

$process = (new ReflectionClass(Process::class))->newInstanceWithoutConstructor();
try {
    $process->__construct('MissingProcessCallback::run');
    Assert::true(false);
} catch (TypeError $error) {
    Assert::contains($error->getMessage(), 'must be a valid callback');
}
$process->__construct(function (): void {
});

final class ExistingProcessCallback
{
    public static function run(): void
    {
    }
}

$process = (new ReflectionClass(Process::class))->newInstanceWithoutConstructor();
$reentered = false;
spl_autoload_register($loader = function (string $class) use ($process, &$reentered): void {
    if ($class !== 'ReentrantProcessCallback') {
        return;
    }
    $reentered = true;
    $process->__construct(function (): void {
    });
    class_alias(ExistingProcessCallback::class, $class);
}, true, true);
try {
    try {
        $process->__construct('ReentrantProcessCallback::run');
        Assert::true(false);
    } catch (Error $error) {
        Assert::contains($error->getMessage(), 'Constructor of Swoole\Process can only be called once');
    }
} finally {
    spl_autoload_unregister($loader);
}
Assert::true($reentered);
?>
--EXPECT--
