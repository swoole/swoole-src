--TEST--
swoole_stdext/stream_method: 0
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$fp = fopen("/tmp/test.txt", "w+");
$rdata = random_bytes(1024);
Assert::greaterThan($fp->write($rdata->base64Encode()), $rdata->length());
$fp->seek(0);
Assert::eq($rdata, $fp->read(8192)->base64Decode());
?>
--EXPECT--
