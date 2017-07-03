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

#write to swoole_buffer
$write_len = $buffer->write(0, $data);
assert($data_len === $write_len);

#read some byte
$read_str = $buffer->read(0, $data_len);
if (strcmp($read_str, $data) == 0) {
    echo "SUCCESS";
}

 ?>

--EXPECT--
SUCCESS
