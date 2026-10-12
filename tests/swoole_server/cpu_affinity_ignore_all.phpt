--TEST--
swoole_server: cpu_affinity_ignore rejects all available CPUs
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_process_affinity();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;
use Swoole\Server;

$cpu = Process::getAffinity()[0];
Assert::true(Process::setAffinity([$cpu]));

$server = new Server('127.0.0.1', 0);
$server->set([
    'cpu_affinity_ignore' => [$cpu],
]);
?>
--EXPECTF--
Fatal error: Swoole\Server::set(): cpu_affinity_ignore excludes all available CPUs in %s on line %d
