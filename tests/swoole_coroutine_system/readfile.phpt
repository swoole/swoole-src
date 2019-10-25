--TEST--
swoole_coroutine_system: readFile
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

go(function () {
    $content = Swoole\Coroutine\System::readFile(TEST_IMAGE);
    Assert::same(md5_file(TEST_IMAGE), md5($content));
});
?>
--EXPECT--
