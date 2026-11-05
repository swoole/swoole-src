--TEST--
swoole_thread/server: synchronous task worker sends its stop callback data before exiting
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Thread;

Assert::setThrowException(true);

const PAYLOAD_SIZE = 1024 * 1024;
$port = get_constant_port(__FILE__);
$server = new Swoole\Server('127.0.0.1', $port, SWOOLE_THREAD);
$server->set([
    'worker_num' => 1,
    'task_worker_num' => 1,
    'task_enable_coroutine' => false,
    'enable_coroutine' => false,
    'log_file' => '/dev/null',
    'log_level' => SWOOLE_LOG_ERROR,
    'init_arguments' => function () {
        global $ready;
        $ready = new Thread\Queue();
        return [$ready];
    },
]);
$server->on('WorkerStart', function (Swoole\Server $server) {
    if (!$server->taskworker) {
        [$ready] = Thread::getArguments();
        $ready->push(true, Thread\Queue::NOTIFY_ALL);
    }
});
$server->on('Receive', function (Swoole\Server $server, int $fd) {
    Assert::integer($server->task($fd));
});
$server->on('Task', function (Swoole\Server $server, int $taskId, int $workerId, int $fd) {
    global $targetFd;
    $targetFd = $fd;
    Assert::true($server->stop());
});
$server->on('Finish', function () {});
$server->on('WorkerStop', function (Swoole\Server $server) {
    global $targetFd;
    if ($server->taskworker && isset($targetFd)) {
        // No reactor or successor is needed: the synchronous task worker must complete this
        // cross-worker write itself, while the event worker continues consuming its pipe.
        Assert::true($server->send($targetFd, str_repeat('t', PAYLOAD_SIZE)));
    }
});
$server->on('Shutdown', function () {
    echo "shutdown\n";
});
$server->addProcess(new Swoole\Process(function () use ($server, $port) {
    [$ready] = Thread::getArguments();
    Assert::true($ready->pop(-1));
    $client = new Swoole\Client(SWOOLE_SOCK_TCP);
    Assert::true($client->connect('127.0.0.1', $port, 5));
    Assert::greaterThan($client->send("task\n"), 0);
    $received = '';
    while (strlen($received) < PAYLOAD_SIZE) {
        $chunk = $client->recv();
        Assert::notEmpty($chunk);
        $received .= $chunk;
    }
    Assert::same($received, str_repeat('t', PAYLOAD_SIZE));
    $client->close();
    echo "delivered\n";
    $server->shutdown();
}));
$server->start();
?>
--EXPECT--
delivered
shutdown
