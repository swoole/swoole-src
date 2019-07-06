--TEST--
swoole_coroutine_scheduler: hook_flags
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

// 1
$sch = new Swoole\Coroutine\Scheduler();
$sch->set(['hook_flags' => SWOOLE_HOOK_ALL,]);
$sch->add(function ($t, $n) {
    usleep($t);
    echo "$n\n";
}, 100000, 'A');
$sch->start();

usleep(1);
echo "B\n";

// 2
$sch = new Swoole\Coroutine\Scheduler();
$sch->set(['hook_flags' => SWOOLE_HOOK_ALL,]);
$sch->add(function ($t, $n) {
    usleep($t);
    echo "$n\n";
}, 100000, 'C');
$sch->start();

?>
--EXPECTF--
int(%d)
B
A
