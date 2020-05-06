--TEST--
swoole_function: log_file
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
define('TMP_LOG_FILE', __DIR__.'/log_file.txt');
swoole_async_set(['log_file' => TMP_LOG_FILE]);
swoole_error_log(SWOOLE_LOG_WARNING, "hello world");
echo file_get_contents(TMP_LOG_FILE);
unlink(TMP_LOG_FILE);
?>
--EXPECTF--
[%s @%d.%d]	WARNING	hello world