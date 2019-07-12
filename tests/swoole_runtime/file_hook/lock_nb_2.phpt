--TEST--
swoole_runtime/file_hook: file_put_contents with LOCK_NB[2]
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
    Assert::same(flock($fp, LOCK_NB | LOCK_EX), true);
    echo "[1] LOCK\n";
    Co::sleep(0.01);
    echo "[1] UNLOCK\n";
    flock($fp, LOCK_UN);
});

go(function () {
    Co::sleep(0.001);
    $fp = fopen(FILE, 'w+');
    echo "[2] LOCK yield\n";
    Assert::assert(flock($fp, LOCK_EX));
    echo "[2] LOCK resume\n";
    flock($fp, LOCK_UN);
    co:sleep(0.002);
    echo "[2] UNLOCK\n";
    fclose($fp);
});

swoole_event_wait();
unlink(FILE);
?>
--EXPECTF--
[1] LOCK
[2] LOCK yield
[1] UNLOCK
[2] LOCK resume
[2] UNLOCK
