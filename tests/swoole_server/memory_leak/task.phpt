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

$GLOBALS['counter1'] = 0;
$GLOBALS['counter2'] = 0;
$GLOBALS['atomic'] = new Swoole\Atomic;

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
    go(function () use ($pm, $chunks) {
        $cli = new Client(SWOOLE_SOCK_TCP);
        if ($cli->connect('127.0.0.1', $pm->getFreePort(), 100) == false) {
            echo "ERROR\n";
            return;
        }
        $cli->send("start\n");
    });
    Swoole\Event::wait();
    $pm->wait();
    $pm->kill();
};

$GLOBALS['test_fn'] = function ($taskId, $data, $chunks) {
    if ($GLOBALS['counter1'] == 0) {
        $GLOBALS['memory_usage_1'] = memory_get_usage();
    }
    $GLOBALS['counter1']++;
    $GLOBALS['counter2'] += (strlen($data));
    Assert::eq($chunks[$taskId], $data);
};

$pm->childFunc = function () use ($pm, $total, $chunks) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set(array(
        'worker_num' => 1,
        'task_worker_num' => 1,
        'log_file' => '/dev/null',
    ));
    $serv->on('WorkerStart', function (Server $serv, $wid) use ($pm) {
        if ($wid == 0) {
            $pm->wakeup();
        }
        $GLOBALS['atomic']->add();
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $_data) use ($chunks) {
        foreach ($chunks as $ch) {
            Assert::greaterThanEq($serv->task($ch), 0);
            usleep(100);
        }
    });
    $serv->on('finish', function (Server $serv, $taskId, $data) use ($pm, $total, $chunks) {
        $GLOBALS['test_fn']($taskId, $data, $chunks);
        if ($GLOBALS['counter2'] == $total) {
            $pm->wakeup();
        }
    });
    $serv->on('task', function (Server $serv, $taskId, $srcWorkerId, $data) use ($pm, $total, $chunks) {
        $GLOBALS['test_fn']($taskId, $data, $chunks);
        return $data;
    });
    $serv->on('WorkerStop', function (Server $serv) use ($total) {
        $GLOBALS['memory_usage_2'] = memory_get_usage();
        Assert::lessThan($GLOBALS['memory_usage_2'] - $GLOBALS['memory_usage_1'], 8192);
        Assert::eq($GLOBALS['counter2'], $total);
        $GLOBALS['atomic']->add();
        echo "DONE\n";
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
Assert::eq($GLOBALS['atomic']->get(), 4);
?>
--EXPECT--
DONE
DONE
