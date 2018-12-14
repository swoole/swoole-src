--TEST--
swoole_buffer: default contruct buffer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$buffer = new swoole_buffer();

assert($buffer instanceof swoole_buffer);

echo "capacity:" . $buffer->capacity . "\n";
echo "length:" . $buffer->length . "\n";

$ret = $buffer->read(0, 10);
assert($ret == false);

 ?>
--EXPECT--
capacity:128
length:0
