--TEST--
swoole_coroutine_system: writeFile use FILE_APPEND
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$filename = __DIR__ . '/tmp_file.txt';
Swoole\Coroutine::create(function () use ($filename) {
    $n = 0;
    $n += Swoole\Coroutine\System::writeFile($filename, "first line\n", FILE_APPEND);
    $n += Swoole\Coroutine\System::writeFile($filename, "second line\n", FILE_APPEND);
    $n += Swoole\Coroutine\System::writeFile($filename, "third line\n", FILE_APPEND);
    Assert::same($n, filesize($filename));
    unlink($filename);
});

?>
--EXPECT--
