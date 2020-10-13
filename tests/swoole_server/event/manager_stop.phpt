--TEST--
swoole_server/event: onManagerStop
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Server;
use Swoole\Atomic;

$pm = new SwooleTest\ProcessManager;
$pm->setWaitTimeout(5);

const FILE = __DIR__ . '/tmp_result.txt';

$atomic = new Atomic();

$pm->parentFunc = function () use ($pm) {
    echo "done\n";
};

$pm->childFunc = function () use ($pm, $atomic) {
    $serv = new Server('127.0.0.1', $pm->getFreePort());
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null'
    ]);
    $serv->on("start", function (Server $serv) use ($atomic) {
        if ($atomic->add() == 2) {
            $serv->shutdown();
        }
    });
    $serv->on("ManagerStart", function (Server $serv) use ($atomic) {
        if ($atomic->add() == 2) {
            $serv->shutdown();
        }
    });
    $serv->on("ManagerStop", function (Server $serv) use ($pm) {
        file_put_contents(FILE, 'manager stop' . PHP_EOL);
        $pm->wakeup();
    });
    $serv->on("Receive", function () { });
    $serv->start();
};

$pm->childFirst();
$pm->run();

echo file_get_contents(FILE);
unlink(FILE);

?>
--EXPECT--
done
manager stop
