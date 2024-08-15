--TEST--
swoole_thread/server: send in user process
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

$serv = new Swoole\Http\Server('127.0.0.1', $port, SWOOLE_THREAD);

$proc = new Swoole\Process(function ($process) use ($serv) {
    [$queue, $atomic] = Thread::getArguments();
    global $port;
    echo $queue->pop(-1);
    $reqUid = uniqid();
    Assert::eq(file_get_contents('http://127.0.0.1:' . $port . '/?uid=' . $reqUid), $reqUid);
    echo "done\n";
    $serv->shutdown();
});
$serv->addProcess($proc);

$proc2 = new Swoole\Process(function ($process) use ($serv) {
    $json = $process->read();
    $data = json_decode($json, true);
    $response = Swoole\Http\Response::create($data['fd']);
    $response->end($data['uid']);
    $response->close();
});
$serv->addProcess($proc2);

$serv->set(array(
    'worker_num' => 1,
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
    $atomic->add();
    $queue->push("begin\n", Thread\Queue::NOTIFY_ALL);
});
$serv->on('WorkerStop', function (Swoole\Server $serv, $workerId) {
    [$queue, $atomic] = Thread::getArguments();
    $atomic->add();
});
$serv->on('Request', function ($req, $resp) use ($serv, $proc2) {
    $resp->detach();
    $proc2->write(json_encode(['fd' => $resp->fd, 'uid' => $req->get['uid']]));
});
$serv->on('shutdown', function () {
    global $queue, $atomic;
    Assert::eq($atomic->get(), 2);
    echo "shutdown\n";
});

$serv->start();
?>
--EXPECT--
begin
done
shutdown
