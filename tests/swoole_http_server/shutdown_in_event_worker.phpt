--TEST--
swoole_http_server: shutdown in worker process
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
    });
    usleep(100000);
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set([
        'worker_num' => 2,
        'log_file' => '/dev/null',
    ]);

    $serv->on('ManagerStart', function (Server $serv) use ($pm) {
        $pm->wakeup();
    });

    $serv->on('workerStop', function ($server) {
        echo "worker exit\n";
    });

    $serv->on('Request', function (Request $request, Response $response) use ($serv, $pm) {
        $response->end('Hello Swoole');
        $serv->shutdown();
        $pm->wakeup();
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
worker exit
worker exit
