--TEST--
swoole_server: stats_file with SWOOLE_BASE and worker_num>1
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

const STATS_FILE = __DIR__ . '/stats.log';
if (is_file(STATS_FILE)) {
    unlink(STATS_FILE);
}

$pm = new ProcessManager;
$pm->initFreePorts(1);

$pm->parentFunc = function ($pid) use ($pm)
{
    go(function() use ($pm, $pid) {
        httpRequest('http://127.0.0.1:' . $pm->getFreePort(0));
        Co::sleep(1);
        for ($i = 0; $i < 4; ++$i) {
            Co::sleep(0.5);
            $content = file_get_contents(STATS_FILE);
            if('' != $content) {
                echo $content;
                break;
            }
        }
        swoole_process::kill($pid);
    });
};

$pm->childFunc = function () use ($pm)
{
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(0), SWOOLE_BASE);
    $server->set([
        'stats_file' => STATS_FILE,
        'worker_num' => 2,
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
start_time: %d
connection_num: 0
accept_count: 1
close_count: 1
worker_num: 2
idle_worker_num: 2
tasking_num: 0
request_count: 1
coroutine_num: 0
[%s]	INFO	Server is shutdown now
