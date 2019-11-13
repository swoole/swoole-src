--TEST--
swoole_library/exec/exec: Fix $output result inconsistency
--SKIPIF--
<?php
require __DIR__ . '/../../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../../include/bootstrap.php';

$fileName = __DIR__ . '/exec_test.php';
file_put_contents($fileName, "1   \r\n2\r\n3\r\n");

exec('php ' . $fileName, $output1);

Swoole\Runtime::enableCoroutine();
go(function () use ($output1, $fileName) {
    exec('php ' . $fileName, $output2);
    Assert::same($output2, $output1);
});

?>
--EXPECT--
