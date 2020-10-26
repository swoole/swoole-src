--TEST--
swoole_server: stats_file
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use function Swoole\Coroutine\run;

const STATS_FILE = __DIR__ . '/stats.log';
if (is_file(STATS_FILE)) {
    unlink(STATS_FILE);
}

$pm = new ProcessManager;
$pm->initFreePorts(1);

$pm->parentFunc = function ($pid) use ($pm)
{
    run(function() use ($pm, $pid) {
        httpRequest('http://127.0.0.1:' . $pm->getFreePort(0));
        for ($i = 0; $i < 4; ++$i) {
            Co::sleep(0.5);
            $content = @file_get_contents(STATS_FILE);
            if ('' != $content) {
                echo $content;
                break;
            }
        }
    });
    echo "\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $mode = SERVER_MODE_RANDOM;
    $worker_num = rand(1, 4);
    echo "mode: $mode\nworker_num: $worker_num\n";
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
        $response->end("<h1>Hello Swoole. #".rand(1000, 9999)."</h1>");
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
mode: %d
worker_num: %d
start_time: %d
connection_num: %d
accept_count: %d
close_count: %d
worker_num: %d
idle_worker_num: %d
task_worker_num: %d
tasking_num: %d
request_count: %d
worker_request_count: %d
worker_dispatch_count: %d
coroutine_num: %d
