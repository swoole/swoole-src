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

$data = "Test: write to swoole_buffer something.";
$data_len = strlen($data);

#写入数据
$write_len = $buffer->write(0, $data);
assert($data_len === $write_len);

//获得数据
$str = $buffer->substr(0, $data_len, true);
$buffer->recycle();
assert($buffer->length == 0);

echo "SUCCESS";

?>

--EXPECT--
SUCCESS
