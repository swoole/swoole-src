--TEST--
swoole_thread/server: base
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Runtime;
use Swoole\Thread;
use Swoole\Thread\Queue;
use Swoole\Thread\Atomic;

$port = get_constant_port(__FILE__);

$serv = new Swoole\Http\Server('127.0.0.1', $port, SWOOLE_THREAD);
$serv->set(array(
    'worker_num' => 4,
    'log_level' => SWOOLE_LOG_ERROR,
    'hook_flags' => SWOOLE_HOOK_ALL,
    'init_arguments' => function () {
        global $queue, $atomic;
        $queue = new Queue();
        $atomic = new Atomic(0);
        return [$queue, $atomic];
    }
));
$serv->on('WorkerStart', function (Swoole\Server $serv, $workerId) use ($port) {
    [$queue, $atomic] = Thread::getArguments();
    Assert::eq(Runtime::getHookFlags(), SWOOLE_HOOK_ALL);
    $output = file_get_contents("http://127.0.0.1:$port/");
    $queue->push($output, Queue::NOTIFY_ALL);
});
$serv->on('Request', function ($req, $resp) {
    usleep(100000);
    $resp->end('DONE');
});
$serv->on('shutdown', function ($server) {
    global $queue, $atomic;
    echo 'shutdown', PHP_EOL;
    Assert::eq($atomic->get(), $server->setting['worker_num']);
});
$serv->addProcess(new Swoole\Process(function ($process) use ($serv) {
    [$queue, $atomic] = Thread::getArguments();
    for ($i = 0; $i < 4; $i++) {
        echo $queue->pop(-1), PHP_EOL;
        $atomic->add(1);
    }
    $serv->shutdown();
}));
$serv->start();
?>
--EXPECT--
DONE
DONE
DONE
DONE
shutdown
