--TEST--
swoole_server: close in onConnect callback
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
use Swoole\Constant;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP );
        if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
            exit("connect failed\n");
        }
        $client->send("close");
        $data = $client->recv();
        Assert::eq($data, "");
        echo "DONE\n";
    });
    Swoole\Event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set([
        'worker_num' => 2,
        'log_file' => TEST_LOG_FILE,
    ]);
    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $reactor_id, $data) {
    });
    $serv->on(Constant::EVENT_CONNECT, function (Server $serv, $fd, $reactor_id) {
        $serv->close($fd);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
