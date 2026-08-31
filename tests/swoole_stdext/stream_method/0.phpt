--TEST--
swoole_stdext/stream_method: 0
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$filepath = "/tmp/test.txt";
$fp = fopen($filepath, "w+");
$rdata = random_bytes(1024);
Assert::greaterThan($fp->write($rdata->base64Encode()), $rdata->length());
$fp->seek(0);
Assert::eq($rdata, $fp->read(8192)->base64Decode());
Assert::eq($fp->stat(), fstat($fp));
Assert::true($fp->sync());
Assert::true($fp->dataSync());
$fp->seek(100);
Assert::true($fp->tell() == 100);
Assert::true($fp->lock(LOCK_SH) == true);
Assert::true($fp->lock(LOCK_UN) == true);
Assert::true($fp->eof() == feof($fp));

$fp->seek(0);
$char = $fp->getChar();
$fp->seek(0);
Assert::eq($char, fgetc($fp));
$fp->seek(0);
$line = $fp->getLine();
$fp->seek(0);
Assert::eq($line, fgets($fp));
Assert::true($fp->truncate(1000));

Assert::true($fp->close());
?>
--EXPECT--
