--TEST--
swoole_thread/server: taskCo
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
use Swoole\Http\Request;
use Swoole\Http\Response;

$port = get_constant_port(__FILE__);

$serv = new Server('127.0.0.1', $port, SWOOLE_THREAD);
$serv->set(array(
    'worker_num' => 2,
    'task_worker_num' => 2,
    'enable_coroutine' => true,
    'init_arguments' => function () {
        global $queue, $atomic;
        $queue = new Swoole\Thread\Queue();
        $atomic = new Swoole\Thread\Atomic(1);
        return [$queue, $atomic];
    }
));
$serv->on('WorkerStart', function (Swoole\Server $serv, $workerId) use ($port) {
    [$queue, $atomic] = Thread::getArguments();
    if ($workerId == 0) {
        $queue->push("begin\n", Thread\Queue::NOTIFY_ALL);
    }
});
$serv->on('task',
    function (Server $server, int $task_id, int $src_worker_id, mixed $data) {
        $server->finish($data * 7);
    }
);
$serv->on('Request',
    function (Request $request, Response $response) use ($serv) {
        $tasks = range(1, 16);
        $result = $serv->taskCo($tasks);
        $response->header('Content-Type', 'application/json');
        $response->end(json_encode(["count" => count($result)]));
    }
);
$serv->on('shutdown', function () {
    global $queue, $atomic;
    echo 'shutdown', PHP_EOL;
    Assert::eq($atomic->get(), 0);
});
$serv->addProcess(new Swoole\Process(function ($process) use ($serv) {
    [$queue, $atomic] = Thread::getArguments();
    global $port;
    echo $queue->pop(-1);
    Co\run(function () use ($port) {
        echo httpGetBody("http://127.0.0.1:{$port}/") . PHP_EOL;
    });
    $atomic->set(0);
    echo "done\n";
    $serv->shutdown();
}));
$serv->start();
?>
--EXPECT--
begin
{"count":16}
done
shutdown
