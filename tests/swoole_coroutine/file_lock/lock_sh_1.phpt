--TEST--
swoole_coroutine/file_lock: lock_sh_1
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

\Swoole\Runtime::enableCoroutine();
$startTime = microtime(true);
go(function () {
    $f = fopen('test.tmp', 'w+');
    $ret = flock($f, LOCK_EX);
    assert($ret);
    co::sleep(0.3);
    $ret = flock($f, LOCK_UN);
    assert($ret);
});

go(function () {
    $f = fopen('test.tmp', 'w+');
    $ret = flock($f, LOCK_SH);
    assert($ret);
    co::sleep(2);
    $ret = flock($f, LOCK_UN);
    assert($ret);
});

go(function () use ($startTime) {
    $f = fopen('test.tmp', 'w+');
    $ret = flock($f, LOCK_SH);
    assert($ret);
    assert((microtime(true) - $startTime) < 1);
    $ret = flock($f, LOCK_UN);
    assert($ret);
});

?>
--EXPECTF--
