--TEST--
swoole_buffer: read and write swoole_buffer
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$buffer = new swoole_buffer();
Assert::isInstanceOf($buffer, swoole_buffer::class);

$data = "Test:write swoole_buffer something.";
$ret = $buffer->write(0, $data);
Assert::eq($buffer->length, strlen($data));

$buffer->clear();
if($buffer->length == 0) {
    echo "SUCCESS";
}

?>
--EXPECT--
SUCCESS
