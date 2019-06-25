--TEST--
swoole_coroutine_scheduler: user yield and resume1
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$sch = new Co\Scheduler;

$sch->set(['max_coroutine' => 100]);

$sch->parallel(10, function ($t, $n) {
    Co::sleep($t);
    echo "Co ".Co::getCid()."\n";
}, 0.05, 'A');

$sch->start();

?>
--EXPECTF--
Co %d
Co %d
Co %d
Co %d
Co %d
Co %d
Co %d
Co %d
Co %d
Co %d
