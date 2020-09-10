--TEST--
swoole_runtime/file_hook: fseek ftell file larger than 2G bug
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

const SIZES = [
    2147724448,
    4 * 1024 * 1024 * 1024,
];

$noHookResults = [];
$fp = fopen(__FILE__, 'r+');
foreach(SIZES as $size) {
    Assert::same(0, fseek($fp, $size));
    $noHookResults[$size] = ftell($fp);
}
fclose($fp);

Swoole\Runtime::enableCoroutine();

Co\run(function () use ($noHookResults) {
    $hookResults = [];
    $fp = fopen(__FILE__, 'r+');
    foreach(SIZES as $size) {
        Assert::same(0, fseek($fp, $size));
        $hookResults[$size] = ftell($fp);
    }
    Assert::same($hookResults, $noHookResults);
    fclose($fp);
});

?>
--EXPECT--
