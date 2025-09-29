--TEST--
swoole_thread/server: listen
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
require __DIR__ . '/functions.inc';

use Swoole\Thread;

$port = get_constant_port(__FILE__);

$serv = new Swoole\Server('127.0.0.1', $port + 1, SWOOLE_THREAD);
$port2 = $serv->listen('127.0.0.1', $port, SWOOLE_SOCK_TCP);
$serv->set(array(
    'worker_num' => 2,
    'log_level' => SWOOLE_LOG_ERROR,
    'open_eof_check' => true,
    'package_eof' => "\r\n",
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
    $json = json_decode(rtrim($data));
    if ($json->type == 'eof') {
        $serv->send($fd, "EOF\r\n");
    }
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
    Co\run(function () use ($port) {
        Co::join([
            Co\go(function () use ($port) {
                thread_server_test_eof_client($port);
            }),
            Co\go(function () use ($port) {
                thread_server_test_eof_client($port + 1);
            })
        ]);
    });
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
