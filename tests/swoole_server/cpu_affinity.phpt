--TEST--
swoole_server: bind event workers to available CPUs
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_process_affinity();
$affinity = Swoole\Process::getAffinity();
skip('requires CPUs 0 and 1', !in_array(0, $affinity) || !in_array(1, $affinity));
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Process;
use Swoole\Server;

$server = new Server('127.0.0.1', get_constant_port(__FILE__), SWOOLE_BASE);
$server->set(array(
    'worker_num' => 1,
    'open_cpu_affinity' => true,
    'cpu_affinity_ignore' => array(0),
    'log_file' => '/dev/null',
));
$server->on('WorkerStart', function (Server $server) {
    echo implode(',', Process::getAffinity()), PHP_EOL;
    $server->shutdown();
});
$server->on('Receive', function () {});
$server->start();
?>
--EXPECT--
1
