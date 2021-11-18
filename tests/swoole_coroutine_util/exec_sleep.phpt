--TEST--
swoole_coroutine_util: coroutine exec
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
Swoole\Event::wait();
$s = microtime(true) - $s;
time_approximate(1, $s);
echo "DONE\n";
?>
--EXPECT--
DONE
