--TEST--
swoole_process: null callback
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$process = new Swoole\Process(function () { });
array_walk($process, function (&$value) {
    $value = null;
});
$process->start();

?>
--EXPECTF--
Warning: Swoole\Process::start(): illegal callback function in %s
