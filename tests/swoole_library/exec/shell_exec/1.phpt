--TEST--
swoole_library/std/exec: Test exec
--SKIPIF--
<?php require __DIR__ . '/../../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();
go(function () {
    $output = shell_exec('md5sum ' . TEST_IMAGE);
    Assert::eq(strstr($output, ' ', true), md5_file(TEST_IMAGE));
});

?>
--EXPECT--
