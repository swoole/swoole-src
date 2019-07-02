--TEST--
swoole_library/std/exec: Test exec
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();
go(function () {
    $data = exec('md5sum ' . TEST_IMAGE, $output, $returnVar);
    Assert::eq($returnVar, 0);
    Assert::eq(strstr(implode(PHP_EOL, $output), ' ', true), md5_file(TEST_IMAGE));
});

?>
--EXPECT--
