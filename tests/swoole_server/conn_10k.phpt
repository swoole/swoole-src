--TEST--
swoole_server: 10k connections
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$count = 0;
$client_map = [];
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    for ($c = MAX_CONCURRENCY_MID; $c--;) {
        go(function () use ($pm, $c) {
            for ($n = MAX_REQUESTS; $n--;) {
                global $count, $client_map;
                $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
                $client_map["{$c}.{$n}"] = $client;
                if ($client->connect('127.0.0.1', $pm->getFreePort(), -1)) {
                    if (++$count === MAX_CONCURRENCY_MID * MAX_REQUESTS) {
                        var_dump($count);
                        echo "DONE\n";
                        $client_map = [];
                        $pm->kill();
                    }
                }
            }
        });
    }
};
$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set([
        "worker_num" => swoole_cpu_num() * 2,
        'log_file' => '/dev/null',
        'max_connection' => MAX_CONCURRENCY_MID * MAX_REQUESTS
    ]);
    $serv->on("WorkerStart", function (Swoole\Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('connect', function () {
        global $count;
        $count++;
    });
    $serv->on('receive', function (Swoole\Server $serv, $fd, $rid, $data) {

    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
int(%d)
DONE
