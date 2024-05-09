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
use Swoole\Thread\Lock;

const SIZE = 2 * 1024 * 1024;

$tm = new \SwooleTest\ThreadManager();
$tm->initFreePorts();

$tm->parentFunc = function () use ($tm) {
    $queue = new Swoole\Thread\Queue();
    $atomic = new Swoole\Thread\Atomic(1);
    $thread = Thread::exec(__FILE__, $queue, $atomic);
    echo $queue->pop(-1);

    $c = MAX_CONCURRENCY_LOW;
    $n = MAX_REQUESTS_LOW;

    for ($i = 0; $i < $c; $i++) {
        go(function () use ($tm, $i, $n, $atomic) {
            $cli = new Co\Client(SWOOLE_SOCK_TCP);
            $cli->set([
                'open_length_check' => true,
                'package_max_length' => 4 * 1024 * 1024,
                'package_length_type' => 'N',
                'package_length_offset' => 0,
                'package_body_offset' => 4,
            ]);
            if ($cli->connect('127.0.0.1', $tm->getFreePort(), 2) == false) {
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
    echo $queue->pop(-1);
};

$tm->childFunc = function ($queue, $atomic) use ($tm) {
    $serv = new Swoole\Server('127.0.0.1', $tm->getFreePort(), SWOOLE_THREAD);
    $serv->set(array(
        'worker_num' => 2,
        'log_level' => SWOOLE_LOG_ERROR,
        'open_length_check' => true,
        'package_max_length' => 4 * 1024 * 1024,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 4,
        'init_arguments' => function () use ($queue, $atomic) {
            return [$queue, $atomic];
        }
    ));
    $serv->on("WorkerStart", function (Swoole\Server $serv, $workerId) use ($queue, $atomic) {
        if ($workerId == 0) {
            $queue->push("begin\n", Thread\Queue::NOTIFY_ALL);
            \Swoole\Timer::tick(200, function ($timerId) use ($atomic, $serv) {
                if ($atomic->get() == 0) {
                    $serv->shutdown();
                    \Swoole\Timer::clear($timerId);
                }
            });
        }
    });
    $serv->on("WorkerStop", function (Swoole\Server $serv, $workerId) use ($queue, $atomic) {
    });
    $serv->on('receive', function (Swoole\Server $serv, $fd, $rid, $data) use ($queue, $atomic) {
        $send_data = str_repeat('A', SIZE - 12) . substr($data, -8, 8);
        $serv->send($fd, pack('N', strlen($send_data)) . $send_data);
    });
    $serv->on('shutdown', function () use ($queue, $atomic) {
        $queue->push("shutdown\n", Thread\Queue::NOTIFY_ALL);
    });
    $serv->start();
};

$tm->run();
?>
--EXPECT--
begin
done
shutdown
