--TEST--
swoole_runtime/file_hook: support io_uring
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
use Swoole\Runtime;
use function Swoole\Coroutine\run;
require __DIR__ . '/../../include/bootstrap.php';

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);
run(function(){
    $filesize = 1048576;
    $content = random_bytes($filesize);
    $fileName = '/tmp/test_file';
    Assert::eq(file_put_contents($fileName, $content), 1048576);
    var_dump(stat($fileName));
    Assert::eq(filesize($fileName), 1048576);
    Assert::eq(file_get_contents($fileName), $content);
    unlink($fileName);
    Assert::true(!file_exists($fileName));

    $stream = fopen($fileName, 'w');
    fwrite($stream, $content);
    Assert::true(fdatasync($stream));
    Assert::true(fsync($stream));
    Assert::eq(file_get_contents($fileName), $content);
    var_dump(fstat($stream));
    fclose($stream);
    unlink($fileName);

    file_put_contents($fileName, $content);
    rename($fileName, $fileName.'aaa');
    Assert::true(!file_exists($fileName));
    Assert::true(file_exists($fileName.'aaa'));
    unlink($fileName.'aaa');

    $directory = '/tmp/test1/test1/test1/test1/test1/test1';
    mkdir($directory, 0755, true);
    Assert::true(is_dir($directory));
    rmdir($directory);
    Assert::true(!is_dir($directory));

    echo 'SUCCESS';
});
?>
--EXPECTF--
array(26) {
  [0]=>
  int(%d)
  [1]=>
  int(%d)
  [2]=>
  int(%d)
  [3]=>
  int(%d)
  [4]=>
  int(%d)
  [5]=>
  int(%d)
  [6]=>
  int(%d)
  [7]=>
  int(%d)
  [8]=>
  int(%d)
  [9]=>
  int(%d)
  [10]=>
  int(%d)
  [11]=>
  int(%d)
  [12]=>
  int(%d)
  ["dev"]=>
  int(%d)
  ["ino"]=>
  int(%d)
  ["mode"]=>
  int(%d)
  ["nlink"]=>
  int(%d)
  ["uid"]=>
  int(%d)
  ["gid"]=>
  int(%d)
  ["rdev"]=>
  int(%d)
  ["size"]=>
  int(%d)
  ["atime"]=>
  int(%d)
  ["mtime"]=>
  int(%d)
  ["ctime"]=>
  int(%d)
  ["blksize"]=>
  int(%d)
  ["blocks"]=>
  int(%d)
}
array(26) {
  [0]=>
  int(%d)
  [1]=>
  int(%d)
  [2]=>
  int(%d)
  [3]=>
  int(%d)
  [4]=>
  int(%d)
  [5]=>
  int(%d)
  [6]=>
  int(%d)
  [7]=>
  int(%d)
  [8]=>
  int(%d)
  [9]=>
  int(%d)
  [10]=>
  int(%d)
  [11]=>
  int(%d)
  [12]=>
  int(%d)
  ["dev"]=>
  int(%d)
  ["ino"]=>
  int(%d)
  ["mode"]=>
  int(%d)
  ["nlink"]=>
  int(%d)
  ["uid"]=>
  int(%d)
  ["gid"]=>
  int(%d)
  ["rdev"]=>
  int(%d)
  ["size"]=>
  int(%d)
  ["atime"]=>
  int(%d)
  ["mtime"]=>
  int(%d)
  ["ctime"]=>
  int(%d)
  ["blksize"]=>
  int(%d)
  ["blocks"]=>
  int(%d)
}
SUCCESS
