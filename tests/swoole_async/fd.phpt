--TEST--
swoole_async: fd reuse
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_debug_version();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
Co::set([
    'log_level' => SWOOLE_LOG_TRACE,
    'trace_flags' => SWOOLE_TRACE_AIO
]);
file_put_contents(TEST_LOG_FILE, '');
swoole_async_write(TEST_LOG_FILE, $content[] = get_safe_random());
swoole_async_write(TEST_LOG_FILE, $content[] = get_safe_random());
swoole_async_write(TEST_LOG_FILE, $content[] = get_safe_random());
swoole_event_wait();
$real_content = file_get_contents(TEST_LOG_FILE);
phpt_var_dump($content, $real_content);
assert($real_content === implode('', $content));
?>
--EXPECTF--
[%s]	TRACE	zif_swoole_async_write(:%d): open write file fd#%d
[%s]	TRACE	zif_swoole_async_write(:%d): reuse write file fd#%d
[%s]	TRACE	zif_swoole_async_write(:%d): reuse write file fd#%d
