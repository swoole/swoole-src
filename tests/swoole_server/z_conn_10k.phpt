--TEST--
swoole_server: 10k connections
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
require __DIR__ . '/../include/config.php';
if ((int)`ulimit -n 2>&1` < MAX_CONCURRENCY_MID * MAX_REQUESTS) {
    skip('ulimit -n failed');
}
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$count = 0;
$client_map = [];
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    for ($c = MAX_CONCURRENCY_MID; $c--;) {
        go(function () use ($pm, $c) {
            for ($n = MAX_REQUESTS; $n--;) {
                global $count, $client_map;
                $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
                $client_map["{$c}.{$n}"] = $client;
                if ($client->connect('127.0.0.1', $pm->getFreePort(), -1)) {
                    if (Assert::assert($client->recv() === 'Hello Swoole!')) {
                        if (++$count === MAX_CONCURRENCY_MID * MAX_REQUESTS) {
                            var_dump($count);
                            echo "DONE\n";
                            $client_map = [];
                            $pm->kill();
                        }
                        continue;
                    }
                } else {
                    echo "ERROR\n";
                    $pm->kill();
                    exit;
                }
            }
        });
    }
    register_shutdown_function(function () {
        global $client_map;
        foreach ($client_map as $client) {
            $client->close();
        }
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        "worker_num" => swoole_cpu_num() * 2,
        'log_file' => '/dev/null',
        'max_connection' => MAX_CONCURRENCY_MID * MAX_REQUESTS
    ]);
    $server->on("WorkerStart", function (Swoole\Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $server->on('connect', function (Swoole\Server $server, int $fd) {
        global $count;
        $count++;
        $server->send($fd, 'Hello Swoole!');
    });
    $server->on('receive', function (Swoole\Server $serv, $fd, $rid, $data) { });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
int(%d)
DONE
