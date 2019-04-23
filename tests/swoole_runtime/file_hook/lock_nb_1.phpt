--TEST--
swoole_runtime/file_hook: file_put_contents with LOCK_NB
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

swoole\runtime::enableCoroutine();

const FILE = __DIR__ . '/test.data';

Swoole\Runtime::enableCoroutine();

go(function () {
    $fp = fopen(FILE, 'w+');
    Assert::assert(flock($fp, LOCK_EX));
    Co::sleep(0.01);
    flock($fp, LOCK_UN);
    fclose($fp);
});


go(function () {
    $fp = fopen(FILE, 'w+');
    Assert::eq(flock($fp, LOCK_NB | LOCK_EX), false);
});

swoole_event_wait();
unlink(FILE);
?>
--EXPECTF--
