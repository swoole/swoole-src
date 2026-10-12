--TEST--
swoole_server: cpu_affinity_ignore ignores unusable CPU IDs
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_process_affinity();
skip('requires two CPUs', count(Swoole\Process::getAffinity()) < 2);
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
use Swoole\Process;

$server = new Server('127.0.0.1', 0);
$affinity = Process::getAffinity();
$outsideAffinity = max($affinity) + 1;

$server->set([
    'cpu_affinity_ignore' => [-1, $outsideAffinity, $affinity[0], $affinity[0]],
]);
$server->set([
    'cpu_affinity_ignore' => [-1, $outsideAffinity],
]);

echo "DONE\n";
?>
--EXPECT--
DONE
