--TEST--
swoole_buffer: default contruct buffer
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
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
