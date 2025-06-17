--TEST--
swoole_process_pool: co\socket reuse port
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Constant;
use Swoole\Coroutine\Client;
use Swoole\Coroutine\Scheduler;
use Swoole\Coroutine\Socket;
use Swoole\Process;
use Swoole\Process\Pool;
use SwooleTest\ProcessManager;

$pm = new ProcessManager();

$pm->parentFunc = function ($pid) use ($pm) {
    $sch = new Scheduler();
    $pids = [];
    $sch->parallel(10, function () use ($pm, &$pids) {
        $cli = new Client(SWOOLE_SOCK_TCP);
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
    Assert::eq(count($pids), IS_MAC_OS ? 1 : 2);
    echo "DONE\n";
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $atomic = new Atomic();
    $pool = new Pool(2);
    $pool->set(['enable_coroutine' => true]);
    $pool->on(Constant::EVENT_WORKER_START, function ($pool, $id) use ($pm, $atomic) {
        $socket = new Socket(AF_INET, SOCK_STREAM, 0);
        $socket->setOption(SOL_SOCKET, SO_REUSEPORT, true);
        $socket->bind('127.0.0.1', $pm->getFreePort());
        $socket->listen(128);

        if ($atomic->add() == 2) {
            $pm->wakeup();
        }
        Process::signal(SIGTERM, function () use ($socket) {
            $socket->cancel();
        });
        while (true) {
            $client = $socket->accept();
            if (!$client) {
                if ($socket->errCode == SOCKET_ECANCELED) {
                    break;
                }
                continue;
            }
            co::sleep(0.005);
            $data = $client->recv();
            if (empty($data)) {
                $client->close();
                break;
            }
            $client->send(serialize(['wid' => $id]));
        }
    });
    $pool->start();
};

$pm->childFirst();
$pm->run();

?>
--EXPECTF--
DONE
