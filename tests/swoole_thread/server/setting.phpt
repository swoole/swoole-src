--TEST--
swoole_thread/server: setting
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Thread;

$port = get_constant_port(__FILE__);
const N = 4;

$serv = new Swoole\Server('127.0.0.1', $port, SWOOLE_THREAD);
$serv->set(array(
    'worker_num' => N,
    'log_level' => SWOOLE_LOG_ERROR,
    'init_arguments' => function () {
        global $queue, $atomic;
        $queue = new Swoole\Thread\Queue();
        $atomic = new Swoole\Thread\Atomic(0);
        return [$queue, $atomic];
    }
));
$serv->on('WorkerStart', function (Swoole\Server $serv, $workerId) use ($port) {
    [$queue, $atomic] = Thread::getArguments();
    Assert::isArray($serv->setting);
    if ($atomic->add(1) == N) {
        $queue->push("begin\n", Thread\Queue::NOTIFY_ALL);
    }
});
$serv->on('receive', function (Swoole\Server $serv, $fd, $rid, $data) {
});
$serv->on('shutdown', function () {
    global $queue, $atomic;
    echo 'shutdown', PHP_EOL;
    Assert::eq($atomic->get(), N);
});
$serv->addProcess(new Swoole\Process(function ($process) use ($serv) {
    [$queue, $atomic] = Thread::getArguments();
    echo $queue->pop(-1);
    echo "done\n";
    $serv->shutdown();
}));
$serv->start();
?>
--EXPECT--
begin
done
shutdown
