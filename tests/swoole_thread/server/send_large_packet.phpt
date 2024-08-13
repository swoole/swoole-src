--TEST--
swoole_thread/server: send large packet
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
    'worker_num' => 2,
    'log_level' => SWOOLE_LOG_ERROR,
    'open_length_check' => true,
    'package_max_length' => 4 * 1024 * 1024,
    'package_length_type' => 'N',
    'package_length_offset' => 0,
    'package_body_offset' => 4,
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
$serv->on("WorkerStop", function (Swoole\Server $serv, $workerId) {
});
$serv->on('receive', function (Swoole\Server $serv, $fd, $rid, $data) {
    $send_data = str_repeat('A', SIZE - 12) . substr($data, -8, 8);
    $serv->send($fd, pack('N', strlen($send_data)) . $send_data);
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

    $c = MAX_CONCURRENCY_LOW;
    $n = MAX_REQUESTS_LOW;

    for ($i = 0; $i < $c; $i++) {
        go(function () use ($i, $n, $atomic, $port) {
            $cli = new Co\Client(SWOOLE_SOCK_TCP);
            $cli->set([
                'open_length_check' => true,
                'package_max_length' => 4 * 1024 * 1024,
                'package_length_type' => 'N',
                'package_length_offset' => 0,
                'package_body_offset' => 4,
            ]);
            if ($cli->connect('127.0.0.1', $port, 2) == false) {
                echo "ERROR\n";
                return;
            }
            for ($i = 0; $i < $n; $i++) {
                $sid = strval(rand(10000000, 99999999));
                $send_data = str_repeat('A', 1000) . $sid;
                $cli->send(pack('N', strlen($send_data)) . $send_data);
                $data = $cli->recv();
                Assert::same(strlen($data), SIZE);
                Assert::same($sid, substr($data, -8, 8));
            }
        });
    }
    Swoole\Event::wait();
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
