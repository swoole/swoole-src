--TEST--
swoole_server: send data in master process
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
use Swoole\Constant;
use Swoole\Timer;
use Swoole\Atomic;

$GLOBALS['data'] = base64_encode(random_bytes(128));
$GLOBALS['atomic'] = new Atomic(0);

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    Co\run(function () use ($pm) {
        $cli = new Co\Client(SWOOLE_SOCK_TCP);
        if ($cli->connect('127.0.0.1', $pm->getFreePort(), 100) == false) {
            echo "ERROR\n";
            return;
        }
        $cli->send($GLOBALS['data']);
        Assert::same($cli->recv(), 'Swoole: '.$GLOBALS['data']);
    });
    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set(array(
        "worker_num" => 2,
        'log_file' => TEST_LOG_FILE,
    ));
    $serv->on(Constant::EVENT_START, function (Server $server) {
        Timer::tick(50, function ($timer) use ($server) {
            if ($GLOBALS['atomic']->get() == 0) {
                return;
            }
            foreach ($server->connections as $fd) {
                $server->send($fd, 'Swoole: ' . $GLOBALS['data']);
            }
            Timer::clear($timer);
        });
    });
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on(Constant::EVENT_RECEIVE, function (Server $serv, $fd, $rid, $data) {
        $GLOBALS['atomic']->set(1);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
