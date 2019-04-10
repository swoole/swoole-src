--TEST--
swoole_buffer: read and write swoole_buffer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$buffer = new swoole_buffer();
Assert::isInstanceOf($buffer, swoole_buffer::class);

$new_size = 256;
$expand_ret = $buffer->expand($new_size);
Assert::eq($new_size, $expand_ret);

echo "buffer size = $buffer->capacity";

?>
--EXPECTF--
buffer size = %d
