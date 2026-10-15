--TEST--
swoole_coroutine: negative http2 settings
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

foreach (['socket_buffer_size', 'http2_header_table_size', 'http2_enable_push',
    'http2_max_concurrent_streams', 'http2_init_window_size', 'http2_max_frame_size',
    'http2_max_header_list_size'] as $option) {
    try {
        Swoole\Coroutine::set([$option => -1]);
        Assert::true(false, 'negative size must throw');
    } catch (Swoole\Exception $exception) {
        Assert::same($exception->getCode(), SWOOLE_ERROR_INVALID_PARAMS);
        Assert::contains($exception->getMessage(), $option);
    }
}
restore_error_handler();
Assert::same($errors, []);

echo "DONE\n";
?>
--EXPECT--
DONE
