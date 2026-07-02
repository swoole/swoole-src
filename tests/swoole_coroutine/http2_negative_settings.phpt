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

Swoole\Coroutine::set([
    'socket_buffer_size' => -1,
    'http2_header_table_size' => -1,
    'http2_enable_push' => -1,
    'http2_max_concurrent_streams' => -1,
    'http2_init_window_size' => -1,
    'http2_max_frame_size' => -1,
    'http2_max_header_list_size' => -1,
]);

restore_error_handler();

Assert::eq(count($errors), 7);
Assert::contains($errors[0], 'socket_buffer_size');
Assert::contains($errors[1], 'http2_header_table_size');
Assert::contains($errors[2], 'http2_enable_push');
Assert::contains($errors[3], 'http2_max_concurrent_streams');
Assert::contains($errors[4], 'http2_init_window_size');
Assert::contains($errors[5], 'http2_max_frame_size');
Assert::contains($errors[6], 'http2_max_header_list_size');

echo "DONE\n";
?>
--EXPECT--
DONE
