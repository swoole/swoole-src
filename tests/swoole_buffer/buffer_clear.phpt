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

$data = "Test:write swoole_buffer something.";
$ret = $buffer->write(0, $data);
assert($buffer->length == strlen($data));

$buffer->clear();
if($buffer->length == 0) {
    echo "SUCCESS";
}

?>

--EXPECT--
SUCCESS
