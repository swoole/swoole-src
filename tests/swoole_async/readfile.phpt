--TEST--
swoole_async: swoole_async_read

--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

swoole_async_readfile(TEST_IMAGE, function ($filename, $content) {
    assert(md5_file($filename) == md5($content));
    echo "SUCCESS\n";
});
?>
--EXPECT--
SUCCESS
