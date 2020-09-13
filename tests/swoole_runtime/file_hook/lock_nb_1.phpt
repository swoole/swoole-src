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

$cid = 0;

go(function () use (&$cid)  {
    $fp = fopen(FILE, 'w+');
    Assert::true(flock($fp, LOCK_EX));
    Co::resume($cid);
    Co::sleep(0.01);
    flock($fp, LOCK_UN);
    fclose($fp);
});

go(function () use (&$cid) {
    $cid = Co::getCid();
    Co::yield();
    $fp = fopen(FILE, 'w+');
    Assert::same(flock($fp, LOCK_NB | LOCK_EX), false);
});

swoole_event_wait();
unlink(FILE);
?>
--EXPECTF--
