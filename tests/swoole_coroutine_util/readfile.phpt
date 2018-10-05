--TEST--
swoole_coroutine_util: Co::readFile

--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $content = Co::readFile(TEST_IMAGE);
    assert(md5_file(TEST_IMAGE) == md5($content));
});
?>
--EXPECT--
