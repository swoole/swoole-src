--TEST--
swoole_atomic: destruct objects in child processe
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$atomic = new swoole_atomic;

$p = new swoole_process(function () use ($atomic) {
    $atomic->wait();
    echo "Child OK\n";
    exit(0);
});
$p->start();

usleep(200000);
echo "Master OK\n";
$atomic->wakeup(1);
$status = swoole_process::wait();
?>
--EXPECT--
Master OK
Child OK
