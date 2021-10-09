--TEST--
swoole_server/event: onWorkerExit
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Constant;
use Swoole\Process;
use Swoole\Server;
use Swoole\Atomic;
use Swoole\Timer;

$pm = new SwooleTest\ProcessManager;
$pm->setWaitTimeout(5);

const FILE = __DIR__ . '/tmp_result.txt';

$atomic = new Atomic();

$pm->setWaitTimeout(5);
$pm->setLogFile(FILE);

$pm->parentFunc = function () use ($pm) {
    usleep(10000);
    Process::kill($pm->getChildPid(), SIGUSR1);
    echo "done\n";
};

$pm->childFunc = function () use ($pm, $atomic) {
    $serv = new Server('127.0.0.1', $pm->getFreePort());

    $serv->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
    ]);

    $serv->on("start", function (Server $serv) use ($atomic, $pm) {
        $pm->writeLog('master start');
    });

    $serv->on(Constant::EVENT_MANAGER_START, function (Server $serv) use ($atomic, $pm) {
        usleep(1000);
        $pm->writeLog('manager start');
    });

    $serv->on(Constant::EVENT_WORKER_START, function (Server $serv) use ($atomic, $pm) {
        if ($atomic->get() == 0) {
            usleep(2000);
        }
        $pm->writeLog('worker start, id=' . $serv->getWorkerId() . ', status=' . $serv->getWorkerStatus());

        if ($atomic->add() == 2) {
            usleep(10000);
            $serv->shutdown();
        } else {
            $serv->timer = Timer::tick(100, function () use ($serv, $pm) {
                $pm->writeLog(
                    'tick, id=' . $serv->getWorkerId() . ', status=' . $serv->getWorkerStatus());
                $pm->wakeup();
            });
        }
    });

    $serv->on(Constant::EVENT_WORKER_EXIT, function (Server $serv) use ($atomic, $pm) {
        $pm->writeLog(
            'worker exit, id=' . $serv->getWorkerId() . ', status=' . $serv->getWorkerStatus());
        Timer::clear($serv->timer);
    });

    $serv->on(Constant::EVENT_WORKER_STOP, function (Server $serv) use ($pm) {
        $pm->writeLog('worker stop');
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
master start
manager start
worker start, id=0, status=2
tick, id=0, status=2
worker exit, id=0, status=3
worker stop
worker start, id=0, status=2
worker stop
