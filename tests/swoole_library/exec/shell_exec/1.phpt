--TEST--
swoole_library/exec/shell_exec: shell_exec
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
    $output = shell_exec('md5sum ' . TEST_IMAGE);
    Assert::same(strstr($output, ' ', true), md5_file(TEST_IMAGE));
});

?>
--EXPECT--
