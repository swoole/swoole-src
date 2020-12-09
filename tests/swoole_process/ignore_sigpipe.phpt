--TEST--
swoole_process: ignore SIGPIPE
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Server;
use Swoole\Constant;

$GLOBALS['data'] = base64_encode(random_bytes(128));

$pm = new SwooleTest\ProcessManager;
$pm->setWaitTimeout(5);

$pm->parentFunc = function ($pid) use ($pm) {
    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set(array(
        "worker_num" => 1,
        'hook_flags' => SWOOLE_HOOK_ALL,
        'log_level' => SWOOLE_LOG_WARNING,
    ));
    $serv->on("WorkerStart", function (Server $serv) use ($pm) {
        $cli = new Co\Client(SWOOLE_SOCK_TCP);
        if ($cli->connect('127.0.0.1', $pm->getFreePort(), 1) == false) {
            echo "ERROR\n";
            return;
        }
        while (1) {
            usleep(10000);
            if ($cli->send($GLOBALS['data']) == false) {
                Assert::eq($cli->errCode, SOCKET_EPIPE);
                break;
            }
        }
        $pm->wakeup();
    });

    $serv->on(Constant::EVENT_CONNECT, function (Server $serv, $fd, $rid) {
        $serv->close($fd);
    });
    $serv->on(Constant::EVENT_RECEIVE, function (Server $serv, $fd, $rid, $data) {

    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
