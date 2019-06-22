--TEST--
swoole_coroutine_system: writeFile
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$content = file_get_contents(TEST_IMAGE);
$filename = __DIR__ . '/tmp_file.jpg';
go(function () use ($filename, $content) {
    $n = Co::writeFile($filename, $content);
    Assert::eq(md5_file($filename), md5_file(TEST_IMAGE));
    Assert::eq($n, filesize($filename));
    unlink($filename);
});
?>
--EXPECT--
