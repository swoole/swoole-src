--TEST--
swoole_process: push
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$process = new Swoole\Process(function(Swoole\Process $worker) {
    echo Co::getCid() . PHP_EOL;
}, false, false, true);
$process->start();
$process::wait();

$process = new Swoole\Process(function(Swoole\Process $worker) {
    echo Co::getCid() . PHP_EOL;
}, false, false, false);
$process->set(['enable_coroutine' => true]);
$process->start();
$process::wait();

?>
--EXPECT--
1
1
