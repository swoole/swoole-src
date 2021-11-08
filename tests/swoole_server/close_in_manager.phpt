--TEST--
swoole_server: close in manager process
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

use function Swoole\Coroutine\run;

const N  = 4;

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    run(function () use ($pm) {
        swoole_loop_n(N, function () use ($pm) {
            go(function () use ($pm) {
                $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
                if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
                    exit("connect failed\n");
                }
                $client->send("close");
                $data = $client->recv();
                Assert::eq($data, "");
            });
        });
    });
    echo "ALL DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $serv->set([
        'worker_num' => 2,
        'log_file' => TEST_LOG_FILE,
    ]);
    $serv->on(Constant::EVENT_MANAGER_START, function ($serv) use ($pm) {
        Timer::after(200, function () use ($serv) {
            foreach ($serv->connections as $fd) {
                $serv->close($fd);
            }
        });
        $pm->wakeup();
    });
    $serv->on(Constant::EVENT_RECEIVE, function (Server $serv, $fd, $reactor_id, $data) {
    });
    $serv->on(Constant::EVENT_CLOSE, function (Server $serv, $fd, $reactor_id) {
        Assert::assert(posix_getpid() != $serv->manager_pid);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
ALL DONE
