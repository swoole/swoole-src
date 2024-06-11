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

use Swoole\Thread;
use  Swoole\Thread\Lock;

const SIZE = 2 * 1024 * 1024;

$tm = new \SwooleTest\ThreadManager();
$tm->initFreePorts(increment: crc32(__FILE__) % 1000);

$tm->parentFunc = function () use ($tm) {
    $queue = new Swoole\Thread\Queue();
    $atomic = new Swoole\Thread\Atomic(1);
    $thread = new Thread(__FILE__, $queue, $atomic);
    echo $queue->pop(-1);
    Co\run(function () use ($tm) {
        $cli = new Co\Client(SWOOLE_SOCK_TCP);
        $cli->set([
            'open_eof_check' => true,
            'package_eof' => "\r\n",
        ]);
        Assert::assert($cli->connect('127.0.0.1', $tm->getFreePort(), 2));
        $cli->send(json_encode(['type' => 'eof']) . "\r\n");
        Assert::eq($cli->recv(), "EOF\r\n");
    });
    $atomic->set(0);
    echo "done\n";
    echo $queue->pop(-1);
};

$tm->childFunc = function ($queue, $atomic) use ($tm) {
    $serv = new Swoole\Server('127.0.0.1', $tm->getFreePort(), SWOOLE_THREAD);
    $serv->set(array(
        'worker_num' => 2,
        'log_level' => SWOOLE_LOG_ERROR,
        'open_eof_check' => true,
        'package_eof' => "\r\n",
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
    $serv->on('receive', function (Swoole\Server $serv, $fd, $rid, $data) {
        $json = json_decode(rtrim($data));
        if ($json->type == 'eof') {
            $serv->send($fd, "EOF\r\n");
        }
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
