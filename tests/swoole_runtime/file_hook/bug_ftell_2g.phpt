--TEST--
swoole_runtime/file_hook: fseek ftell file larger than 2G bug
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

const FILE_NAME = __DIR__ . '/bigfile.txt';

// generate file
$content = str_repeat('0', 1024 * 1024); // 1MB
$fp = fopen(FILE_NAME, 'w+');
for($i = 0; $i < 2049; ++$i) {
    fwrite($fp, $content);
}
fclose($fp);

Assert::same(1024 * 1024 * 2049, filesize(FILE_NAME));

Swoole\Runtime::enableCoroutine();

Co\run(function () {
    $fp = fopen(FILE_NAME, 'r');
    Assert::notEq($fp, false);
    Assert::same(0, fseek($fp, 2147724450, SEEK_CUR));
    Assert::same(2147724450, ftell($fp));
    fclose($fp);
});
unlink(FILE_NAME);

?>
--EXPECT--