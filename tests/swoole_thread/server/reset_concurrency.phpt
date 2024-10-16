--TEST--
swoole_http_server: reset concurrency [SWOOLE_THREAD]
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine\Http\Client;
use Swoole\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use Swoole\Thread\Atomic;
use Swoole\Thread;
use function Swoole\Coroutine\run;

const N = 64;
const WORKER_NUM = 4;

$port = get_constant_port(__FILE__);

$serv = new Swoole\Http\Server('127.0.0.1', $port, SWOOLE_THREAD);
$serv->set(array(
    'worker_num' => WORKER_NUM,
    'max_concurrency' => 160,
    'log_level' => SWOOLE_LOG_ERROR,
    'log_file' => '/dev/null',
    'init_arguments' => function () {
        global $queue, $atomic1, $atomic2;
        $queue = new Swoole\Thread\Queue();
        $atomic1 = new Swoole\Thread\Atomic(0);
        $atomic2 = new Swoole\Thread\Atomic(0);
        return [$queue, $atomic1, $atomic2];
    }
));
$serv->on('WorkerStart', function (Server $serv, $workerId) use ($port) {
    [$queue, $atomic1, $atomic2] = Thread::getArguments();
    if ($atomic1->add() == WORKER_NUM) {
        $queue->push("begin\n", Thread\Queue::NOTIFY_ALL);
    }
});
$serv->on('WorkerStop', function (Server $serv, $workerId) {
    echo 'WORKER STOP', PHP_EOL;
});
$serv->on('pipeMessage', function (Server $serv, $wid, $msg) {
    swoole_implicit_fn('bailout');
});
$serv->on('Request', function (Request $req, Response $resp) use ($serv) {
    [$queue, $atomic1, $atomic2] = Thread::getArguments();
    $c = $atomic2->add();
    if ($c < N) {
        Co::sleep(100);
    } elseif ($c == N) {
        $stats = $serv->stats();
        Assert::eq($stats['concurrency'], N);
        $wid = $serv->getWorkerId();
        for ($i = 0; $i < WORKER_NUM; $i++) {
            if ($i !== $wid) {
                $serv->sendMessage('error', $i);
            }
        }
        swoole_implicit_fn('bailout');
    } else {
        $stats = $serv->stats();
        Assert::eq($stats['concurrency'], 1);
        $resp->end(json_encode($stats));
    }
});
$serv->on('shutdown', function () {
    global $queue, $atomic1, $atomic2;
    echo 'SHUTDOWN', PHP_EOL;
    Assert::eq($atomic1->get(), WORKER_NUM * 2);
    Assert::eq($atomic2->get(), N + 1);
});
$serv->addProcess(new Swoole\Process(function ($process) use ($serv, $port) {
    [$queue, $atomic1, $atomic2] = Thread::getArguments();
    $queue->pop(-1);
    run(function () use ($port, $serv, $atomic1, $queue) {
        $n = N;
        $coroutines = [];
        while ($n--) {
            $coroutines[] = go(function () use ($port) {
                $client = new Client('127.0.0.1', $port);
                $client->set(['timeout' => 10]);
                Assert::eq($client->get('/'), false);
                Assert::eq($client->getStatusCode(), SWOOLE_HTTP_CLIENT_ESTATUS_SERVER_RESET);
            });
        }

        Co::join($coroutines);

        while (1) {
            if ($atomic1->get() == WORKER_NUM * 2) {
                break;
            }
            Co::sleep(0.1);
        }

        $client = new Client('127.0.0.1', $port);
        Assert::assert($client->get('/'));
        $stats = json_decode($client->getBody());
        Assert::eq($stats->concurrency, 1);
        $serv->shutdown();

        echo "DONE\n";
    });
    $serv->shutdown();
}));
$serv->start();
?>
--EXPECT--
DONE
WORKER STOP
WORKER STOP
WORKER STOP
WORKER STOP
SHUTDOWN
