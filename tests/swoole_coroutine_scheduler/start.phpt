--TEST--
swoole_coroutine_scheduler: user yield and resume1
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$sch = new Co\Scheduler;

$sch->set(['max_coroutine' => 100]);

$sch->add(function ($t, $n) {
    Co::sleep($t);
    echo "$n\n";
}, 0.2, 'A');

$sch->add(function ($t, $n) {
    Co::sleep($t);
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
