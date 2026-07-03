--TEST--
swoole_function: swoole_error_log
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$logFile = tempnam(sys_get_temp_dir(), 'swoole-error-log-');
if ($logFile === false) {
    throw new RuntimeException('failed to create temp log file');
}

register_shutdown_function(static function () use ($logFile) {
    if (is_file($logFile)) {
        @unlink($logFile);
    }
});

const ERROR_1 = 888888;
const ERROR_2 = 999999;

swoole_async_set(['log_file' => $logFile]);
swoole_error_log(SWOOLE_LOG_NOTICE, "hello 1");
swoole_error_log_ex(SWOOLE_LOG_NOTICE, ERROR_1, "hello 2");

swoole_ignore_error(ERROR_2);
swoole_error_log_ex(SWOOLE_LOG_NOTICE, ERROR_2, "hello 3");

$content = file_get_contents($logFile);
Assert::contains($content, 'hello 1');
Assert::contains($content, 'hello 2');
Assert::contains($content, '(ERRNO ' . ERROR_1 . ')');
Assert::notContains($content, 'hello 3');
?>
--EXPECT--
