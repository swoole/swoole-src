--TEST--
swoole_server/memory_leak: task
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Server;
use Swoole\Coroutine\Client;

$pm = new SwooleTest\ProcessManager;

$counter1 = new Swoole\Atomic\Long();
$counter2 = new Swoole\Atomic\Long();

$n = MAX_REQUESTS;
$chunks = [];
$total = 0;
while ($n--) {
    $len = random_int(4 * 1024, 1024 * 1024);
    $chunks[] = random_bytes($len);
    $total += $len;
}

$pm->setWaitTimeout(-1);

$pm->parentFunc = function ($pid) use ($pm, $chunks) {
    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($counter1, $counter2, $pm, $total, $chunks) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set(array(
        'worker_num' => 2,
        'log_file' => '/dev/null',
    ));
    $serv->on("WorkerStart", function (Server $serv, $wid) use ($pm, $chunks) {
        $GLOBALS['memory_usage_1'] = memory_get_usage();
        foreach ($chunks as $ch) {
            Assert::greaterThan($serv->sendMessage($ch, 1 - $wid), 0);
            usleep(10);
        }
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $_data) use ($chunks) {

    });
    $serv->on('pipeMessage', function (Server $serv, $wid, $data) use ($counter2, $counter1, $pm, $total, $chunks) {
        $counter1->add();
        $counter2->add(strlen($data));
        if ($counter2->get() == $total * 2) {
            $pm->wakeup();
        }
    });
    $serv->on('WorkerStop', function (Server $serv) use ($counter2, $total) {
        $GLOBALS['memory_usage_2'] = memory_get_usage();
        Assert::lessThan($GLOBALS['memory_usage_2'] - $GLOBALS['memory_usage_1'], 8192);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
