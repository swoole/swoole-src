--TEST--
swoole_server/memory_leak: length
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
    $pkt = pack('N', $len) . random_bytes($len);
    $chunks[] = $pkt;
    $total += strlen($pkt);
}

$pm->setWaitTimeout(-1);

$pm->parentFunc = function ($pid) use ($pm, $chunks, $total) {
    $clients = [];
    for ($i = 0; $i < MAX_CONCURRENCY_MID; $i++) {
        go(function () use ($pm, $i, $chunks, &$clients, $total) {
            $cli = new Client(SWOOLE_SOCK_TCP);
            $cli->set([
                'open_length_check' => true,
                'package_max_length' => 4 * 1024 * 1024,
                'package_length_type' => 'N',
                'package_length_offset' => 0,
                'package_body_offset' => 4,
            ]);
            if ($cli->connect('127.0.0.1', $pm->getFreePort(), 100) == false) {
                echo "ERROR\n";
                return;
            }
            $count = 0;
            foreach ($chunks as $data) {
                $count += $cli->send($data);
                usleep(10);
            }
            Assert::eq($count, $total);
            $clients[] = $cli;
        });
    }
    Swoole\Event::wait();
    $pm->wait();
    $pm->kill();
};

phpt_var_dump(
    'total all: ' . number_format(MAX_CONCURRENCY_MID * $total) .
    ', n packets: ' . MAX_REQUESTS .
    ', n clients: ' . MAX_CONCURRENCY_MID .
    ', total: ' . number_format($total)
);

$pm->childFunc = function () use ($pm, $counter1, $total, $counter2) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(array(
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_length_check' => true,
        'package_max_length' => 4 * 1024 * 1024,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 4,
    ));
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('connect', function (Server $serv, $fd, $rid) {
        $GLOBALS['bytes_' . $fd] = 0;
        $GLOBALS['count_' . $fd] = 0;
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data) use ($pm, $counter1, $total, $counter2) {
        if ($counter1->get() == 0) {
            $GLOBALS['memory_usage_1'] = memory_get_usage();
        }
        $counter1->add(strlen($data));
        $counter2->add();
        $GLOBALS['bytes_' . $fd] += strlen($data);
        $GLOBALS['count_' . $fd]++;

        if ($GLOBALS['count_' . $fd] == MAX_REQUESTS) {
            phpt_var_dump(
                'bytes: ' . number_format($counter1->get()) .
                ', count: ' . $counter2->get() .
                ', data: ' . strlen($data) .
                ', client bytes: ' . number_format($GLOBALS['bytes_' . $fd]) .
                ', client count: ' . $GLOBALS['count_' . $fd]
            );
        }

        if ($counter1->get() == MAX_CONCURRENCY_MID * $total) {
            $pm->wakeup();
        }
    });
    $serv->on('close', function (Server $serv, $fd, $rid) {
    });
    $serv->on('WorkerStop', function () use ($total, $counter2) {
        $GLOBALS['memory_usage_2'] = memory_get_usage();
        Assert::lessThan($GLOBALS['memory_usage_2'] - $GLOBALS['memory_usage_1'], 8192);
        Assert::eq($counter2->get(), MAX_CONCURRENCY_MID * MAX_REQUESTS);
        echo "DONE\n";
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
