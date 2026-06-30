--TEST--
swoole_process: read rejects invalid size
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
$process = new Swoole\Process(function () {});
var_dump($process->read(0));
?>
--EXPECTF--
Warning: Swoole\Process::read(): size must be greater than 0 in %s on line %d
bool(false)
