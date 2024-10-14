--TEST--
swoole_http_server: reset concurrency [SWOOLE_PROCESS]
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Client;
use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Table;
use Swoole\Atomic;
use function Swoole\Coroutine\run;

const N = 64;

$counter = new Atomic(0);
$table = new Table(1024);
$table->column('pid', Table::TYPE_INT);
$table->create();

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    run(function () use ($pm) {
        $n = N;
        $coroutines = [];
        while ($n--) {
            $coroutines[] = go(function () use ($pm) {
                $client = new Client('127.0.0.1', $pm->getFreePort());
                $client->set(['timeout' => 10]);
                Assert::eq($client->get('/'), false);
                Assert::eq($client->getStatusCode(), SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET);
            });
        }

        Co::sleep(0.1);
        $pm->wait();

        $client = new Client('127.0.0.1', $pm->getFreePort());
        Assert::assert($client->get('/'));
        $stats = json_decode($client->getBody());
        Assert::eq($stats->concurrency, 1);

        /**
         * PROCESS 模式下 Worker 进程退出时连接不会被关闭，这与 BASE 模式不同，因此需要先关闭服务器，其他正在运行的协程才会获得返回值
         */
        $pm->kill();

        Co::join($coroutines);
        echo "DONE\n";
    });
};

$pm->childFunc = function () use ($pm, $counter, $table) {
    $http = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $http->set([
        'worker_num' => 4,
        'max_concurrency' => 160,
        'log_file' => '/dev/null',
    ]);
    $http->on('workerStart', function ($server, $wid) use ($pm, $table) {
        if ($wid === 0) {
            $pm->wakeup();
        }
        $pid = posix_getpid();
        $table->set('worker_' . $wid, ['pid' => $pid]);
        // echo "Worker #{$wid}(pid=$pid) is started\n";
    });
    $http->on('request', function (Request $request, Response $response) use ($http, $counter, $table) {
        $c = $counter->add();
        if ($c < N) {
            Co::sleep(100);
        } elseif ($c == N) {
            $stats = $http->stats();
            Assert::eq($stats['concurrency'], N);
            $pid = posix_getpid();
            foreach ($table as $val) {
                if ($val['pid'] !== $pid) {
                    posix_kill($val['pid'], SIGKILL);
                }
            }
            posix_kill($pid, SIGKILL);
        } else {
            $stats = $http->stats();
            Assert::eq($stats['concurrency'], 1);
            $response->end(json_encode($stats));
        }
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
