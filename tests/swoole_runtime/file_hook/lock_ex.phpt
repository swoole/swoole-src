--TEST--
swoole_runtime/file_hook: file_put_contents with LOCK_EX
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

swoole\runtime::enableCoroutine();

const FILE = __DIR__ . '/test.data';

$n = 10;
while ($n--) {
    go(function () use ($n) {
        $data = str_repeat('A', 8192 * 100);
        file_put_contents(FILE, $data, LOCK_EX);
        echo "$n OK\n";
    });
}

swoole_event_wait();
unlink(FILE);
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
