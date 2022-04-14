--TEST--
swoole_server: dispatch_mode = 3
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_valgrind();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
const WORKER_N = 16;

use Swoole\Coroutine\Client;
use Swoole\Timer;
use Swoole\Event;
use Swoole\Server;

global $stats;
$stats = array();
$count = 0;

$pm = new SwooleTest\ProcessManager;
$pm->initFreePorts();
$pm->parentFunc = function ($pid) use ($pm) {
    global $count, $stats;
    for ($i = 0; $i < MAX_CONCURRENCY; $i++) {
        go(function () use ($pm) {
            $cli = new Client(SWOOLE_SOCK_TCP);
            $cli->set([
                'package_eof' => "\r\n\r\n",
                'open_eof_split' => true,
            ]);
            $r = $cli->connect(TCP_SERVER_HOST, $pm->getFreePort(), 1);
            Assert::assert($r);
            for ($i = 0; $i < MAX_REQUESTS; $i++) {
                $cli->send("hello world\r\n\r\n");
                Co::sleep(0.001);
            }
            $cli->count = 0;
            for ($i = 0; $i < MAX_REQUESTS; $i++) {
                $data = $cli->recv();
                global $stats;
                $wid = trim($data);
                if (isset($stats[$wid])) {
                    $stats[$wid]++;
                } else {
                    $stats[$wid] = 1;
                }
                $cli->count++;
                if ($cli->count == MAX_REQUESTS) {
                    $cli->close();
                }
            }
        });
    }
    Event::wait();
    $pm->kill();
    phpt_var_dump($stats);
    Assert::eq(count($stats), WORKER_N);
    Assert::lessThan($stats[5], MAX_REQUESTS);
    Assert::lessThan($stats[10], MAX_REQUESTS);
    Assert::same(array_sum($stats), MAX_REQUESTS * MAX_CONCURRENCY);
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set(array(
        'worker_num' => WORKER_N,
        'dispatch_mode' => 3,
        'package_eof' => "\r\n\r\n",
        'enable_coroutine' => false,
        'open_eof_split' => true,
        'log_file' => '/dev/null',
    ));
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $rid, $data) {
        if ($serv->worker_id == 10 or $serv->worker_id == 5) {
            usleep(5000);
        }
        $serv->send($fd, $serv->worker_id . "\r\n\r\n");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
