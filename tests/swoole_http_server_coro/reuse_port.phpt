--TEST--
swoole_http_server_coro: reuse port
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Atomic;
use Swoole\Constant;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;
use Swoole\Coroutine\Scheduler;
use Swoole\Process;
use Swoole\Process\Pool;
use SwooleTest\ProcessManager;

$pm = new ProcessManager();

$pm->parentFunc = function ($pid) use ($pm) {
    $sch = new Scheduler();
    $pids = [];
    $sch->parallel(10, function () use ($pm, &$pids) {
        $cli = new Client('127.0.0.1', $pm->getFreePort());
        $ret = $cli->get('/hello');
        if (!$ret) {
            echo "ERROR [3]\n";
            return;
        }
        $result = unserialize($cli->getBody());
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
    $atomic = new Atomic();
    $pool = new Pool(2);
    $pool->set(['enable_coroutine' => true]);
    $pool->on(Constant::EVENT_WORKER_START, function ($pool, $id) use ($pm, $atomic) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), false, true);
        $server->handle('/', function ($request, $response) {
            $response->end(serialize(['wid' => posix_getpid()]));
        });
        if ($atomic->add() == 2) {
            $pm->wakeup();
        }
        Process::signal(SIGTERM, function () use ($server) {
            $server->shutdown();
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
