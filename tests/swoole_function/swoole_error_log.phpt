--TEST--
swoole_function: swoole_error_log
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const LOG_FILE = __DIR__ . '/log';
if (is_file(LOG_FILE)) {
    unlink(LOG_FILE);
}

const ERROR_1 = 888888;
const ERROR_2 = 999999;

swoole_async_set(['log_file' => LOG_FILE]);
swoole_error_log(SWOOLE_LOG_NOTICE, "hello 1");
swoole_error_log_ex(SWOOLE_LOG_NOTICE, ERROR_1, "hello 2");

swoole_ignore_error(ERROR_2);
swoole_error_log_ex(SWOOLE_LOG_NOTICE, ERROR_2, "hello 3");

$content = file_get_contents(LOG_FILE);
Assert::contains($content, 'hello 1');
Assert::contains($content, 'hello 2');
Assert::contains($content, '(ERRNO ' . ERROR_1 . ')');
Assert::notContains($content, 'hello 3');
unlink(LOG_FILE);
?>
--EXPECT--
