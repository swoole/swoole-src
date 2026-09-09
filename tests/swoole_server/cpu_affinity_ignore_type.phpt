--TEST--
swoole_server: cpu_affinity_ignore requires an array
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$server = new Server('127.0.0.1', 0);
$server->set([
    'cpu_affinity_ignore' => 0,
]);
?>
--EXPECTF--
Fatal error: Swoole\Server::set(): cpu_affinity_ignore must be array in %s on line %d
