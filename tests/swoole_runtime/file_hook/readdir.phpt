--TEST--
swoole_runtime/file_hook: readdir
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
Swoole\Runtime::enableCoroutine();

$list0 = scandir('/tmp');
sort($list0);

Co\run(function () use ($list0) {
    $handle = opendir('/tmp');
    Assert::notEmpty($handle);
    $list1 = [];
    while (false !== ($entry = readdir($handle))) {
        $list1[] = "$entry";
    }
    closedir($handle);
    sort($list1);
    Assert::eq($list0, $list1);
});
?>
--EXPECT--
