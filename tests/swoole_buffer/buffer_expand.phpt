--TEST--
swoole_buffer: read and write swoole_buffer
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

$new_size = 256;
$expand_ret = $buffer->expand($new_size);
assert($new_size == $expand_ret);

echo "buffer size = $buffer->capacity";

?>

--EXPECTF--
buffer size = %d
