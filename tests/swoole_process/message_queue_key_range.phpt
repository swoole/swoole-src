--TEST--
swoole_process: reject message queue keys outside key_t
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_linux();
skip('64-bit only', PHP_INT_SIZE < 8);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$process = new Swoole\Process(function () {});
var_dump(@$process->useQueue(1 << 32));
?>
--EXPECT--
bool(false)
