--TEST--
swoole_server: cpu_affinity_ignore ignores unusable CPU IDs
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$server = new Server('127.0.0.1', 0);
$cpuNum = swoole_cpu_num();

$server->set([
    'cpu_affinity_ignore' => [-1, $cpuNum, 0, 0],
]);
$server->set([
    'cpu_affinity_ignore' => [-1, $cpuNum],
]);
$server->set([
    'cpu_affinity_ignore' => range(0, $cpuNum - 1),
]);

echo "DONE\n";
?>
--EXPECT--
DONE
