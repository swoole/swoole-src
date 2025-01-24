--TEST--
swoole_thread/server: Github #5662
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Thread;
use Swoole\Thread\Queue;

$port = get_constant_port(__FILE__);
$server = new Swoole\Http\Server('127.0.0.1', $port, SWOOLE_THREAD);
$server->set([
	'log_file' => '/dev/null',
	'worker_num' => 2,
	'max_request' => 5,
	'init_arguments' => function () {
        global $queue;
        $queue = new Queue();
        return [$queue];
    }
]);
$server->on('WorkerStart', function (Swoole\Server $server, $workerId) {
    [$queue] = Thread::getArguments();
    $queue->push('start', Queue::NOTIFY_ALL);
});
$server->addProcess(new Swoole\Process(function ($process) use ($server, $port) {
	[$queue] = Thread::getArguments();
	Assert::true($queue->pop(-1) == 'start');
	for ($i = 0; $i < 20; $i++) {
        Assert::true(file_get_contents("http://127.0.0.1:{$port}/") == 'OK');
    }
    $server->shutdown();
}));
$server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
    $response->end('OK');
});
$server->start();
?>
--EXPECT--
