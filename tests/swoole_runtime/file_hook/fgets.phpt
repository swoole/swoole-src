--TEST--
swoole_runtime/file_hook: fgets
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$testFn = function () {
    $fp = fopen(__FILE__, 'r');
    $lines[] = fgets($fp);
    fclose($fp);
    return $lines;
};

Swoole\Runtime::enableCoroutine(false);
$lines = $testFn();

Co\run(function () use ($testFn, $lines) {
    Swoole\Runtime::enableCoroutine();
    $lines_2 = $testFn();
    Swoole\Runtime::enableCoroutine(false);
    Assert::eq($lines, $lines_2);
});
?>
--EXPECT--
