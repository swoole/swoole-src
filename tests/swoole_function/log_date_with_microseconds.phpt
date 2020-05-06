--TEST--
swoole_function: log_date_with_microseconds
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
swoole_async_set(['log_date_with_microseconds' => true]);
swoole_error_log(SWOOLE_LOG_WARNING, "hello world");
?>
--EXPECTF--
[%s<.%d> @%d.%d]	WARNING	hello world