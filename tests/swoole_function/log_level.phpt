--TEST--
swoole_function: log_level
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
swoole_async_set(['log_level' => SWOOLE_LOG_NOTICE]);
swoole_error_log(SWOOLE_LOG_INFO, "hello info");
swoole_error_log(SWOOLE_LOG_NOTICE, "hello notice");
swoole_error_log(SWOOLE_LOG_WARNING, "hello warning");
?>
--EXPECTF--
[%s]	NOTICE	hello notice
[%s]	WARNING	hello warning