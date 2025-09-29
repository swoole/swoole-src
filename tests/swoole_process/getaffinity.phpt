--TEST--
swoole_process: getAffinity
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_process_affinity();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;
$r = Process::getAffinity();
Assert::isArray($r);
Assert::eq(count($r), swoole_cpu_num());

Assert::assert(Process::setAffinity([0, 1]));
Assert::eq(Process::getAffinity(), [0, 1]);
?>
--EXPECT--
