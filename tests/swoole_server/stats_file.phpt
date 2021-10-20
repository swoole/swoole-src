--TEST--
swoole_server: stats_file
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use function Swoole\Coroutine\run;

const STATS_FILE = __DIR__ . '/stats.log';
$rm_fn = function () {
    if (is_file(STATS_FILE)) {
        unlink(STATS_FILE);
    }
};
$rm_fn();

$pm = new ProcessManager;
$pm->initFreePorts(1);

$pm->parentFunc = function ($pid) use ($pm) {
    run(function () use ($pm, $pid) {
        httpRequest('http://127.0.0.1:' . $pm->getFreePort(0));
        for ($i = 0; $i < 4; ++$i) {
            Co::sleep(0.5);
            $content = @file_get_contents(STATS_FILE);
            if ('' != $content) {
                $stats = [];
                swoole_string($content)->split("\n")->each(function ($value, $key) use (&$stats) {
                    [$k, $v] = swoole_string($value)->split(":");
                    $stats[$k] = trim($v);
                });
                Assert::keyExists($stats, 'connection_num');
                Assert::keyExists($stats, 'request_count');
                break;
            }
        }
    });
    echo "\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $mode = SERVER_MODE_RANDOM;
    $worker_num = rand(1, 4);
    phpt_var_dump("mode: $mode\nworker_num: $worker_num\n");
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(0), $mode);
    $server->set([
        'stats_file' => STATS_FILE,
        'log_file' => DEV_NULL,
        'worker_num' => $worker_num,
    ]);
    $server->on('ManagerStart', function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function ($request, $response) {
        $response->end("<h1>Hello Swoole. #" . rand(1000, 9999) . "</h1>");
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
$rm_fn();
?>
--EXPECT--
