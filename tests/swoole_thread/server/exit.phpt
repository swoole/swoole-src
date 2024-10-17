--TEST--
swoole_thread/server: exit
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Thread;
use Swoole\Http\Server;

const CODE = 235;
const SIZE = 2 * 1024 * 1024;
$port = get_constant_port(__FILE__);

$serv = new Server('127.0.0.1', $port, SWOOLE_THREAD);
$serv->set(array(
    'worker_num' => 2,
    'log_file' => '/dev/null',
    'log_level' => SWOOLE_LOG_ERROR,
    'enable_coroutine' => false,
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
    if ($atomic1->add() == 2) {
        $queue->push("begin\n", Thread\Queue::NOTIFY_ALL);
    }
    echo 'worker start', PHP_EOL;
});
$serv->on('workerError', function (Server $serv, $workerId, $workerPid, $status, $signal) {
    Assert::eq($status, CODE);
    echo 'worker error', PHP_EOL;
});
$serv->on('WorkerStop', function (Server $serv, $workerId) {
    [$queue, $atomic1, $atomic2] = Thread::getArguments();
});
$serv->on('Request', function ($req, $resp) use ($serv) {
    if ($req->server['request_uri'] == '/exit') {
        swoole_implicit_fn('bailout', CODE);
    }
});
$serv->on('shutdown', function () {
    global $queue, $atomic1, $atomic2;
    echo 'shutdown', PHP_EOL;
    Assert::eq($atomic1->get(), 3);
});
$serv->addProcess(new Swoole\Process(function ($process) use ($serv) {
    [$queue, $atomic] = Thread::getArguments();
    global $port;
    echo $queue->pop(-1);

    $rs = @file_get_contents('http://127.0.0.1:' . $port . '/exit');
    Assert::false($rs);

    usleep(200_000);
    echo "done\n";
    $serv->shutdown();
}));
$serv->start();
?>
--EXPECTF--
worker start
worker start
begin
worker error
worker start
done
shutdown
