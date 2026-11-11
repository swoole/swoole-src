--TEST--
swoole_server: empty task_tmpdir is rejected without aborting
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$server = new Swoole\Server('127.0.0.1', 0, SWOOLE_BASE);
$server->set(['worker_num' => 1, 'task_tmpdir' => '']);
echo "RETURNED\n";
?>
--EXPECTF--
%A
RETURNED
