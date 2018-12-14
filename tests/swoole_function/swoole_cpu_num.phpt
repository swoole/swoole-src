--TEST--
swoole_function: swoole_cpu_num
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$cpu_num = swoole_cpu_num();
echo "cpu_num: $cpu_num";

?>
--EXPECTF--
cpu_num: %d
