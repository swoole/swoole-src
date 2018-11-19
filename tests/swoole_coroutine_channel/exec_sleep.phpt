--TEST--
swoole_coroutine_channel: coroutine exec
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$s = microtime(true);
for ($i = MAX_PROCESS_NUM; $i--;) {
    go(function () {
        co::exec('sleep 1');
    });
}
swoole_event_wait();
$use = microtime(true) - $s;
assert($use <= 2);
echo "DONE\n";
?>
--EXPECT--
DONE
