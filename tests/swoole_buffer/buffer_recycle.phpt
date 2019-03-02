--TEST--
swoole_buffer: read and write swoole_buffer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$buffer = new swoole_buffer();
Assert::isInstanceOf($buffer, swoole_buffer::class);

$data = "Test: write to swoole_buffer something.";
$data_len = strlen($data);

#写入数据
$write_len = $buffer->write(0, $data);
Assert::eq($data_len, $write_len);

//获得数据
$str = $buffer->substr(0, $data_len, true);
$buffer->recycle();
Assert::eq($buffer->length, 0);

echo "SUCCESS";

?>
--EXPECT--
SUCCESS
