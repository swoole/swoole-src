--TEST--
swoole_runtime/file_hook: support io_uring
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
use Swoole\Runtime;
use function Swoole\Coroutine\run;
use Swoole\Coroutine\WaitGroup;
require __DIR__ . '/../include/bootstrap.php';

Runtime::enableCoroutine(SWOOLE_HOOK_ALL);

$setting = [
    'iouring_workers' => 32,
    'iouring_entries' => 30000,
];

if (defined('SWOOLE_IOURING_SQPOLL')) {
    $setting['iouring_flag'] = SWOOLE_IOURING_SQPOLL;
}

swoole_async_set($setting);

$results = [];
for ($i = 1; $i <= 10000; $i++) {
    $results[$i] = random_bytes(rand(8192, 8192 * 3));
}

run(function() use ($results) {
    $filesize = 1048576;
    $content = random_bytes($filesize);
    $fileName = '/tmp/test_file';
    Assert::eq(file_put_contents($fileName, $content), 1048576);
    var_dump(stat($fileName));
    for ($i = 0; $i < 100; $i++) {
        Assert::eq(filesize($fileName), 1048576);
        Assert::eq(file_get_contents($fileName), $content);
    }
    unlink($fileName);
    Assert::true(!file_exists($fileName));

    $stream = fopen($fileName, 'w');
    fwrite($stream, $content);
    if (PHP_VERSION_ID >= 80100) {
        Assert::true(fdatasync($stream));
        Assert::true(fsync($stream));
    }
    Assert::eq(file_get_contents($fileName), $content);
    var_dump(fstat($stream));
    fclose($stream);
    unlink($fileName);

    file_put_contents($fileName, $content);
    rename($fileName, $fileName.'aaa');
    Assert::true(!file_exists($fileName));
    Assert::true(file_exists($fileName.'aaa'));
    unlink($fileName.'aaa');

    $directory = '/tmp/a/b/c/d/e/f';
    mkdir($directory, 0755, true);
    Assert::true(is_dir($directory));
    rmdir($directory);
    Assert::true(!is_dir($directory));

	$waitGroup = new WaitGroup();
    for ($i = 1; $i <= 10000; $i++) {
        go(function() use ($waitGroup, $i, $results){
            $waitGroup->add();
            file_put_contents('/tmp/file'.$i, $results[$i]);
            Assert::true($results[$i] == file_get_contents('/tmp/file'.$i));
            file_put_contents('/tmp/file'.$i, $results[$i], FILE_APPEND);
            file_put_contents('/tmp/file'.$i, $results[$i], FILE_APPEND);
            Assert::true(strlen($results[$i]) * 3 == strlen(file_get_contents('/tmp/file'.$i)));
            $waitGroup->done();
        });
    }
	$waitGroup->wait();
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
