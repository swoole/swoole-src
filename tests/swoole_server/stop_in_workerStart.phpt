--TEST--
swoole_server: stop worker in worker start
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$server = new Server('127.0.0.1', get_one_free_port(), SWOOLE_PROCESS);

$atomic = new Swoole\Atomic(0);
$atomic2 = new Swoole\Atomic(0);

$server->set([
    'worker_num' => 1
]);

$server->on('Receive', function (Server $server, int $fd, int $reactorId, string $data) {
});

$server->on('start', function () use ($atomic) {
    $atomic->add(1);
});

$server->on('WorkerStart', function (Server $server, int $workerId) use ($atomic) {
    if ($atomic->add(1) == 2) {
        $server->stop();
    }
});

$server->on('WorkerStop', function (Server $server, int $workerId) use ($atomic2) {
    usleep(100000);
    if ($atomic2->add(1) == 1) {
        $server->shutdown();
    }
});
$server->start();
?>
--EXPECTF--
