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
$pool->set(['max_package_size' => -1]);

restore_error_handler();

Assert::eq(count($errors), 1);
Assert::contains($errors[0], 'max_package_size');

echo "DONE\n";
?>
--EXPECT--
DONE
