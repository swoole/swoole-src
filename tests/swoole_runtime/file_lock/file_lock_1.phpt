--TEST--
swoole_runtime/file_lock: file_lock_1
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
die("skip not support");
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

\Swoole\Runtime::enableCoroutine();
const FILE = __DIR__ . '/test.data';
$startTime = microtime(true);
go(function () use ($startTime) {
    $f = fopen(FILE, 'w+');
    flock($f, LOCK_EX);
    co::sleep(0.1);
    flock($f, LOCK_UN);

    flock($f, LOCK_SH);
    flock($f, LOCK_UN);
    Assert::assert((microtime(true) - $startTime) < 1);
});
go(function () {
    $f = fopen(FILE, 'w+');
    flock($f, LOCK_SH);
    co::sleep(2);
    flock($f, LOCK_UN);
});
swoole_event_wait();
unlink(FILE);
?>
--EXPECTF--
