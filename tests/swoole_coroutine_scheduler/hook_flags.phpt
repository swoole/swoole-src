--TEST--
swoole_coroutine_scheduler: hook_flags
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$sch = scheduler();

$sch->set(['hook_flags' => SWOOLE_HOOK_ALL,]);

$sch->add(function ($t, $n) {
    sleep($t);
    echo "$n\n";
}, 0.2, 'A');

$sch->add(function ($t, $n) {
    sleep($t);
    echo "$n\n";
}, 0.1, 'B');

$sch->add(function () {
    var_dump(Co::getCid());
});

$sch->start();

?>
--EXPECTF--
int(%d)
B
A
