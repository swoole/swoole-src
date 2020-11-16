--TEST--
swoole_coroutine_system: writeFile use FILE_APPEND
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\System;
use function Swoole\Coroutine\run;

$filename = __DIR__ . '/tmp_file.txt';
run(function () use ($filename) {
    $n = 0;
    $n += System::writeFile($filename, "first line\n", FILE_APPEND);
    $n += System::writeFile($filename, "second line\n", FILE_APPEND);
    $n += System::writeFile($filename, "third line\n", FILE_APPEND);
    Assert::same($n, filesize($filename));
    Assert::same(md5_file($filename), md5(System::readFile($filename)));
    unlink($filename);
});

?>
--EXPECT--
