--TEST--
swoole_server/event: onShutdown
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Server;

$pm = new SwooleTest\ProcessManager;

const SIZE = 8192 * 5;
const FILE = __DIR__ . '/tmp_resule.txt';

$pm->parentFunc = function ($pid) use ($pm) {
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort());
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
    ]);
    $serv->on("start", function (Server $serv) {
        $serv->shutdown();
    });
    $serv->on("shutdown", function (Server $serv) use ($pm) {
        file_put_contents(FILE, 'master shutdown' . PHP_EOL);
        $pm->wakeup();
    });
    $serv->on("Receive", function (Server $serv, $fd, $reactorId, $data) {
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();

echo file_get_contents(FILE);
unlink(FILE);
?>
--EXPECT--
master shutdown
