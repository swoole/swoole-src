--TEST--
swoole_process_pool: negative max_package_size
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$errors = [];
set_error_handler(function (int $errno, string $errstr) use (&$errors) {
    $errors[] = $errstr;
    return true;
});

$pool = new Swoole\Process\Pool(1);
try {
    $pool->set(['max_package_size' => -1]);
    Assert::true(false, 'invalid size must throw');
} catch (Swoole\Exception $exception) {
    Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
    Assert::contains($exception->getMessage(), 'max_package_size');
}

restore_error_handler();

Assert::same($errors, []);

echo "DONE\n";
?>
--EXPECT--
DONE
