--TEST--
swoole_windows: bootstrap constants
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
if (stripos(PHP_OS, 'WIN') !== 0) {
    die('skip Windows only');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Assert::true(is_win());
Assert::same('NUL', DEV_NULL);
Assert::same(sys_get_temp_dir() . '/swoole.log', TEST_LOG_FILE);
Assert::same(sys_get_temp_dir() . '/swoole.pid', TEST_PID_FILE);
Assert::same('\\', DIRECTORY_SEPARATOR);

echo "DONE\n";
?>
--EXPECT--
DONE
