--TEST--
swoole_runtime/file_lock: async file
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

// disable file hook
Swoole\Runtime::enableCoroutine(SWOOLE_HOOK_ALL & ~SWOOLE_HOOK_FILE);

$FILE = __DIR__ . '/test.data';
$startTime = microtime(true);

go(function () use ($startTime, $FILE) {
    $f = fopen("async.file://" . $FILE, 'w+');
    flock($f, LOCK_EX);
    co::sleep(0.1);
    flock($f, LOCK_UN);

    flock($f, LOCK_SH);
    flock($f, LOCK_UN);
    Assert::assert((microtime(true) - $startTime) < 1);
});

go(function () use ($FILE) {
    $f = fopen("async.file://" . $FILE, 'w+');
    flock($f, LOCK_SH);
    co::sleep(2);
    flock($f, LOCK_UN);
});

Swoole\Event::wait();
unlink($FILE);
?>
--EXPECT--
