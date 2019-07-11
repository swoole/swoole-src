--TEST--
swoole_runtime/file_lock: lock_nb
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
const FILE = __DIR__ . '/test.data';
\Swoole\Runtime::enableCoroutine();
go(function () {
    $fp = fopen(FILE, 'w+');
    Assert::assert(flock($fp, LOCK_EX));
    $fp2 = fopen(FILE, 'w+');
    Assert::assert(!flock($fp2, LOCK_EX | LOCK_NB));
});
swoole_event_wait();
unlink(FILE);
?>
--EXPECTF--
