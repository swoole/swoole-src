--TEST--
swoole_coroutine/file_lock: lock_nb
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

\Swoole\Runtime::enableCoroutine();
go(function () {
    $fp = fopen('test.tmp', 'w+');
    assert(flock($fp, LOCK_EX));
    $fp2 = fopen('test.tmp', 'w+');
    assert(!flock($fp2, LOCK_EX | LOCK_NB));
});

?>
--EXPECTF--
