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
    flock($f, LOCK_EX);
    co::sleep(0.01);
    flock($f, LOCK_UN);
});
go(function () {
    $f = fopen('test.tmp', 'w+');
    flock($f, LOCK_SH);
    assert((microtime(true) - $startTime) < 1);
    flock($f, LOCK_UN);
});
go(function () {
    $f = fopen('test.tmp', 'w+');
    flock($f, LOCK_SH);
    co::sleep(2);
    flock($f, LOCK_UN);
});

?>
--EXPECTF--
