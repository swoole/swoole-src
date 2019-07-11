--TEST--
swoole_runtime/file_hook: file_put_contents with LOCK_SH
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

swoole\runtime::enableCoroutine();

$n = 10;
while ($n--) {
    go(function () use ($n) {
        $data = readfile_with_lock(TEST_IMAGE);
        Assert::same(md5_file(TEST_IMAGE), md5($data));
        echo "$n OK\n";
    });
}

swoole_event_wait();
?>
--EXPECTF--
%d OK
%d OK
%d OK
%d OK
%d OK
%d OK
%d OK
%d OK
%d OK
%d OK
