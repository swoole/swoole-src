--TEST--
swoole_function: log_date_format
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
swoole_async_set(['log_date_format' => 'day %d of %B in the year %Y. Time: %I:%S %p']);
swoole_error_log(SWOOLE_LOG_WARNING, "hello world");
?>
--EXPECTF--
[day %d of May in the year %d. Time: %d:%d %s @%d.%d]	WARNING	hello world