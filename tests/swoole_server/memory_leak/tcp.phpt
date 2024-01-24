--TEST--
swoole_server/memory_leak: tcp
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Atomic\Long;
use Swoole\Server;
use Swoole\Coroutine\Client;

$pm = new SwooleTest\ProcessManager;

$counter = new Long();
$n = MAX_REQUESTS;
$chunks = [];
$total = 0;
while ($n--) {
    $len = random_int(4 * 1024, 1024 * 1024);
    $chunks[] = random_bytes($len);
    $total += $len;
}

$pm->parentFunc = function ($pid) use ($pm, $chunks) {
    $clients = [];
    for ($i = 0; $i < MAX_CONCURRENCY_MID; $i++) {
        go(function () use ($pm, $i, &$total, $chunks, &$clients) {
            $cli = new Client(SWOOLE_SOCK_TCP);
            if ($cli->connect('127.0.0.1', $pm->getFreePort(), 100) == false) {
                echo "ERROR\n";
                return;
            }
            foreach ($chunks as $data) {
                $cli->send($data);
                usleep(100);
            }
            $clients[] = $cli;
        });
    }
    Swoole\Event::wait();
    $pm->wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $counter, $total) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $serv->set(array(
        'worker_num' => 1,
        'log_file' => '/dev/null',
    ));
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('connect', function (Server $serv, $fd, $rid) {

    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data) use ($pm, $counter, $total) {
        if ($counter->get() == 0) {
            $GLOBALS['memory_usage_1'] = memory_get_usage();
        }
        if ($counter->add(strlen($data)) == MAX_CONCURRENCY_MID * $total) {
            $pm->wakeup();
        }
    });
    $serv->on('close', function (Server $serv, $fd, $rid) {
    });
    $serv->on('WorkerStop', function () use ($total) {
        $GLOBALS['memory_usage_2'] = memory_get_usage();
        Assert::lessThan($GLOBALS['memory_usage_2'] - $GLOBALS['memory_usage_1'], 8192);
        echo "DONE\n";
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
