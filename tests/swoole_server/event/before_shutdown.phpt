--TEST--
swoole_server/event: onBeforeShutdown
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Event;
use Swoole\Server;

const SIZE = 8192 * 5;
const FILE = __DIR__ . '/tmp_result.txt';

$pm = new SwooleTest\ProcessManager;

$pm->setLogFile(FILE);

$pm->parentFunc = function ($pid) use ($pm) {
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort());
    $serv->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
    ]);
    $serv->on("start", function (Server $serv) use ($pm) {
        $pm->writeLog('master start');
        Event::add(STDIN, function ($fp) {
            echo fread($fp, 8192);
        });
        $serv->shutdown();
    });
    $serv->on("BeforeShutdown", function (Server $serv) use ($pm) {
        $pm->writeLog('before master shutdown');
        Event::del(STDIN);
    });
    $serv->on("shutdown", function (Server $serv) use ($pm) {
        $pm->writeLog('master shutdown');
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
master start
before master shutdown
master shutdown
