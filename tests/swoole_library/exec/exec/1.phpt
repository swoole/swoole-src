--TEST--
swoole_library/exec/exec: Test exec
--SKIPIF--
<?php
require __DIR__ . '/../../../include/skipif.inc';
skip_if_command_not_found('md5sum');
?>
--FILE--
<?php
require __DIR__ . '/../../../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();
go(function () {
    $data = exec('md5sum ' . TEST_IMAGE, $output, $returnVar);
    Assert::same($returnVar, 0);
    Assert::same(strstr(implode(PHP_EOL, $output), ' ', true), md5_file(TEST_IMAGE));
});

?>
--EXPECT--
