--TEST--
swoole_buffer: read and write swoole_buffer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$buffer = new swoole_buffer();
assert($buffer instanceof swoole_buffer);

$data = "Test: write to swoole_buffer something.";
$data_len = strlen($data);

#write to swoole_buffer
$write_len = $buffer->append($data);
assert($data_len === $write_len);

#read some byte
$read_str = $buffer->read(0, $data_len);
if (strcmp($read_str, $data) == 0) {
    echo "SUCCESS";
}

?>
--EXPECT--
SUCCESS
