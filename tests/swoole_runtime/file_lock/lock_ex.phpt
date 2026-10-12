--TEST--
swoole_runtime/file_lock: file_lock_1
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

\Swoole\Runtime::enableCoroutine();
$file = tempnam(sys_get_temp_dir(), 'swoole-flock-');
$shared = new Swoole\Coroutine\Channel(1);
$release = new Swoole\Coroutine\Channel(1);
go(function () use ($file, $shared, $release) {
    $f = fopen($file, 'w+');
    Assert::true(flock($f, LOCK_EX));
    co::sleep(0.01);
    Assert::true(flock($f, LOCK_UN));

    // The other coroutine keeps its shared lock until we acquire ours too.
    Assert::true($shared->pop(2));
    Assert::true(flock($f, LOCK_SH | LOCK_NB));
    Assert::true(flock($f, LOCK_UN));
    $release->push(true);
    fclose($f);
});
go(function () use ($file, $shared, $release) {
    $f = fopen($file, 'w+');
    Assert::true(flock($f, LOCK_SH));
    $shared->push(true);
    Assert::true($release->pop(2));
    Assert::true(flock($f, LOCK_UN));
    fclose($f);
});
Swoole\Event::wait();
unlink($file);
?>
--EXPECTF--
