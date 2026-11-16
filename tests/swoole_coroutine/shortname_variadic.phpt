--TEST--
swoole_coroutine: go alias preserves variadic parameters and accepts callback arguments
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$original = new ReflectionFunction('swoole_coroutine_create');
$alias    = new ReflectionFunction('go');
Assert::true($alias->isVariadic());
Assert::same($alias->getNumberOfParameters(), $original->getNumberOfParameters());
Assert::same($alias->getNumberOfRequiredParameters(), $original->getNumberOfRequiredParameters());
$result = null;
Assert::greaterThan(go(function ($first, $second) use (&$result) {
    $result = [$first, $second];
}, 'first', 42), 0);
Assert::same($result, ['first', 42]);
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
