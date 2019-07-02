--TEST--
swoole_coroutine_scheduler: hook_flags
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$sch = new Swoole\Coroutine\Scheduler();

$sch->set(['hook_flags' => SWOOLE_HOOK_ALL,]);

$sch->add(function ($t, $n) {
    usleep($t);
    echo "$n\n";
}, 200000, 'A');

$sch->add(function ($t, $n) {
    usleep($t);
    echo "$n\n";
}, 100000, 'B');

$sch->add(function () {
    var_dump(Co::getCid());
});

$sch->start();

?>
--EXPECTF--
int(%d)
B
A
