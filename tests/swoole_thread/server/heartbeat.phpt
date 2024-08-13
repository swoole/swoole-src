--TEST--
swoole_thread/server: heartbeat
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Thread;

const SIZE = 2 * 1024 * 1024;
$port = get_constant_port(__FILE__);

$serv = new Swoole\Server('127.0.0.1', $port, SWOOLE_THREAD);
$serv->set(array(
    'worker_num' => 1,
    'log_level' => SWOOLE_LOG_ERROR,
    'heartbeat_check_interval' => 1,
    'heartbeat_idle_time' => 2,
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
$serv->on('receive', function (Swoole\Server $serv, $fd, $rid, $data) {
});
$serv->on('shutdown', function () {
    global $queue, $atomic;
    echo 'shutdown', PHP_EOL;
    Assert::eq($atomic->get(), 0);
});
$serv->addProcess(new Swoole\Process(function ($process) use ($serv) {
    [$queue, $atomic] = Thread::getArguments();
    global $port;
    echo $queue->pop(-1);

    $client = new Swoole\Client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC);
    if (!$client->connect('127.0.0.1', $port, 5, 0)) {
        echo "Error: " . $client->errCode;
        die("\n");
    }
    $s1 = time();
    Assert::same(@$client->recv(), '');
    $s2 = time();
    Assert::assert($s2 - $s1 > 1);

    $atomic->set(0);
    echo "done\n";
    $serv->shutdown();
}));
$serv->start();
?>
--EXPECT--
begin
done
shutdown
