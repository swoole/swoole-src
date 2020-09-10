--TEST--
swoole_server: new twice
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    $fn = function () use ($pm) {
        $cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
        $cli->connect('127.0.0.1', $pm->getFreePort(), 0.5) or die("ERROR");
        $cli->send("signal") or die("ERROR");
    };
    $fn();
    $pm->wait();
    $fn();
};

$pm->childFunc = function () use ($pm) {
    ini_set('swoole.display_errors', 'Off');
    $n = 2;
    while ($n--) {
        $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
        $serv->set(array(
            "worker_num" => 1,
            'enable_coroutine' => false,
            'log_file' => '/dev/null',
        ));
        $serv->on("WorkerStart", function (Server $serv) use ($pm) {
            echo "WorkerStart\n";
            $pm->wakeup();
        });
        $serv->on('receive', function (Server $serv, $fd, $rid, $data) {
            $serv->shutdown();
        });
        $serv->start();
    }
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
WorkerStart
WorkerStart
