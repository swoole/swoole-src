--TEST--
swoole_server: getSocket
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Client;
use Swoole\Server;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    Co\Run(function () use ($pm) {
        $cli = new Client(SWOOLE_SOCK_TCP);
        $r = $cli->connect(TCP_SERVER_HOST, $pm->getFreePort(), 1);
        Assert::assert($r);
        $cli->send("test");
        $data = $cli->recv();
        Assert::same($data, 'Socket');
        $cli->send('shutdown');
        $cli->close();
        echo "SUCCESS\n";
    });
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server(TCP_SERVER_HOST, $pm->getFreePort());
    $socket = $serv->getSocket();
    $serv->set([
        "worker_num" => 1,
        'log_file' => '/dev/null',
    ]);
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on("Receive", function (Server $serv, $fd, $rid, $data) use ($socket) {
        if (trim($data) == 'shutdown') {
            $serv->shutdown();
            return;
        } else {
            if (PHP_VERSION_ID > 80000) {
                $serv->send($fd, get_class($socket));
            } else {
                $serv->send($fd, get_resource_type($socket));
            }
        }
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
