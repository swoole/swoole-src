--TEST--
swoole_process: affinity CPU ID range
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_linux();
skip_if_no_process_affinity();

$status = file_get_contents('/proc/self/status');
preg_match('/^Cpus_allowed_list:\s*(.+)$/m', $status, $matches);
skip('cannot read allowed CPU list', empty($matches[1]));

$cpuRanges = explode(',', trim($matches[1]));
$lastRange = explode('-', end($cpuRanges));
$lastCpu = (int) end($lastRange);
skip('requires an affinity CPU ID outside swoole_cpu_num range', $lastCpu < swoole_cpu_num());
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;

$status = file_get_contents('/proc/self/status');
preg_match('/^Cpus_allowed_list:\s*(.+)$/m', $status, $matches);

$cpus = [];
foreach (explode(',', trim($matches[1])) as $range) {
    $bounds = array_map('intval', explode('-', $range, 2));
    foreach (range($bounds[0], $bounds[1] ?? $bounds[0]) as $cpu) {
        $cpus[] = $cpu;
    }
}

Assert::same(Process::getAffinity(), $cpus);
Assert::true(Process::setAffinity($cpus));
Assert::same(Process::getAffinity(), $cpus);
?>
--EXPECT--
