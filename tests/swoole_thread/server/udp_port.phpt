--TEST--
swoole_thread/server: listen udp port
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Thread;
use Swoole\Timer;
use Swoole\WebSocket\Server;

$port = get_constant_port(__FILE__);

$serv = new Server('127.0.0.1', $port, SWOOLE_THREAD);
$serv->set(array(
    'worker_num' => 2,
    'log_level' => SWOOLE_LOG_ERROR,
    'reload_async' => true,
    'init_arguments' => function () {
        global $queue, $atomic;
        $queue = new Swoole\Thread\Queue();
        $atomic = new Swoole\Thread\Atomic(0);
        return [$queue, $atomic];
    }
));
$udp = $serv->addListener('127.0.0.1', $port + 1, SWOOLE_SOCK_UDP);
$udp->on('packet', function ($serv, $data, $addr) {
    echo "udp packet\n";
    $serv->sendto($addr['address'], $addr['port'], $data);
});
$serv->on('WorkerStart', function (Swoole\Server $serv, $workerId) use ($port) {
    [$queue, $atomic] = Thread::getArguments();
    if ($atomic->add() == 1) {
        $queue->push("begin\n", Thread\Queue::NOTIFY_ALL);
    }
    echo "worker start\n";
});
$serv->on('message', function (Server $server, $frame) {
    echo "message\n";
});
$serv->on('workerExit', function (Server $server, $wid) {
    var_dump('worker exit: ' . $wid);
    Timer::clearAll();
});
$serv->on('shutdown', function (Server $server) {
    global $queue, $atomic;
    echo 'shutdown', PHP_EOL;
    Assert::eq($atomic->get(), $server->setting['worker_num']);
});
$serv->addProcess(new Swoole\Process(function ($process) use ($serv) {
    [$queue, $atomic] = Thread::getArguments();
    global $port;
    echo $queue->pop(-1);
    Co\run(function () use ($port) {
        $udp_sock = stream_socket_client('udp://127.0.0.1:' . ($port + 1), $errno, $errstr);
        $pkt = random_bytes(1024);
        fwrite($udp_sock, $pkt);
        $data = fread($udp_sock, 1024);
        Assert::eq($pkt, $data);
    });
    echo "done\n";
    $serv->shutdown();
}));
$serv->start();
?>
--EXPECT--
worker start
worker start
begin
udp packet
done
shutdown
