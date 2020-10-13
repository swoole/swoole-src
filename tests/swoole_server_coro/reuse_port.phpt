--TEST--
swoole_server_coro: reuse port
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use SwooleTest\ProcessManager;
use Swoole\Coroutine\Socket;
use Swoole\Constant;
use Swoole\Process;
use Swoole\Coroutine\Server\Connection;

$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    $sch = new Swoole\Coroutine\Scheduler();
    $pids = [];
    $sch->parallel(10, function () use ($pm, &$pids) {
        $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        if (!$cli->connect('127.0.0.1', $pm->getFreePort())) {
            echo "ERROR [1]\n";
            return;
        }
        if (!$cli->send("hello\n")) {
            echo "ERROR [2]\n";
            return;
        }
        $ret = $cli->recv();
        if (!$ret) {
            echo "ERROR [3]\n";
            return;
        }
        $result = unserialize($ret);
        if (!$result) {
            echo "ERROR [4]\n";
            return;
        }
        $pids[$result['wid']] = 1;
    });
    $sch->start();
    Assert::eq(count($pids), 2);
    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {

    $atomic = new \Swoole\Atomic();
    $pool = new Swoole\Process\Pool(2);
    $pool->set(['enable_coroutine' => true]);
    $pool->on(Constant::EVENT_WORKER_START, function ($pool, $id) use ($pm, $atomic) {
        $server = new Swoole\Coroutine\Server('127.0.0.1', $pm->getFreePort(), false, true);
        if ($atomic->add() == 2) {
            $pm->wakeup();
        }
        Process::signal(SIGTERM, function () use ($server) {
            $server->shutdown();
        });
        $server->handle(function (Connection $conn) {
            Co::sleep(0.005);
            $data = $conn->recv();
            if (empty($data)) {
                $conn->close();
            }
            $conn->send(serialize(['wid' => posix_getpid()]));
        });
        $server->start();
    });
    $pool->start();
};

$pm->childFirst();
$pm->run();

?>
--EXPECTF--
DONE
