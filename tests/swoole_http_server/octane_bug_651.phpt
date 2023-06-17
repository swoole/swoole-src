--TEST--
swoole_http_server: Octane bug 651 https://github.com/laravel/octane/issues/651
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($client->get('/'));
        Assert::eq($client->getBody(), 'timeout');
        $pm->kill();
    });
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_TCP);
    $http->set(['log_file' => '/dev/null']);

    $timerTable = new Swoole\Table(250);
    $timerTable->column('worker_pid', Swoole\Table::TYPE_INT);
    $timerTable->column('time', Swoole\Table::TYPE_INT);
    $timerTable->column('fd', Swoole\Table::TYPE_INT);
    $timerTable->create();

    $http->on("WorkerStart", function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });

    $http->on('start', function ($server) use ($timerTable) {
        Swoole\Timer::tick(500, function ($id) use ($timerTable, $server) {
            foreach ($timerTable as $workerId => $row) {
                if ((time() - $row['time']) > 3) {
                    $timerTable->del($workerId);
                    $newRes = Swoole\Http\Response::create($server, $row['fd']);;
                    if ($newRes) {
                        Swoole\Timer::clear($id);
                        $newRes->status(408);
                        $newRes->end('timeout');
                        Swoole\Process::kill($row['worker_pid'], 9);
                        return;
                    }
                }
            }
        });
    });

    $http->on('Request', function ($request, $response) use ($http, $timerTable) {
        $timerTable->set($http->getWorkerId(), [
            'worker_pid' => $http->getWorkerPid(),
            'time' => time(),
            'fd' => $request->fd,
        ]);
        sleep(10);
        $response->end('Hello');
        $timerTable->del($http->getWorkerId());
    });

    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
DONE
