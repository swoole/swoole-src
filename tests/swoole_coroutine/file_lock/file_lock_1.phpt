--TEST--
swoole_coroutine/file_lock: file_lock_1
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

\Swoole\Runtime::enableCoroutine();
$startTime = microtime(true);
go(function () use ($startTime) {
    $f = fopen('test.tmp', 'w+');
    flock($f, LOCK_EX);
    co::sleep(0.01);
    flock($f, LOCK_UN);
    flock($f, LOCK_SH);
    flock($f, LOCK_UN);
    assert((microtime(true) - $startTime) < 1);
});
go(function () {
    $f = fopen('test.tmp', 'w+');
    flock($f, LOCK_SH);
    co::sleep(2);
    flock($f, LOCK_UN);
});

?>
--EXPECTF--
