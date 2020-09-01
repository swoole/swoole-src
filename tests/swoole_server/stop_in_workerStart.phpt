--TEST--
swoole_server: stop worker in worker start
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$server = new Server('127.0.0.1', get_one_free_port());

$server->set([
    'worker_num' => 1
]);
$server->on('Receive', function(Server $server, int $fd, int $reactorId, string $data){
});
$server->on('WorkerStart', function(Server $server, int $workid){
    $server->stop();
});
$server->on('WorkerStop',function(Server $server, int $workid){
    $server->shutdown();
});
$server->start();
?>
--EXPECTF--
[%s]	INFO	Server is shutdown now
