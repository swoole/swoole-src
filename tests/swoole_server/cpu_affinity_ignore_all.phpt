--TEST--
swoole_server: cpu_affinity_ignore rejects all available CPUs
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_process_affinity();
skip('requires CPU 1', !in_array(1, Swoole\Process::getAffinity()));
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;
use Swoole\Server;

Assert::true(Process::setAffinity([1]));

$server = new Server('127.0.0.1', 0);
$server->set([
    'cpu_affinity_ignore' => [1],
]);
?>
--EXPECTF--
Fatal error: Swoole\Server::set(): cpu_affinity_ignore excludes all available CPUs in %s on line %d
