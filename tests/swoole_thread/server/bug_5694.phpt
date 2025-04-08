--TEST--
swoole_thread/server: Github #5694
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
use Swoole\Thread\Queue;

$port = get_constant_port(__FILE__);
$server = new Swoole\Http\Server('127.0.0.1', $port, SWOOLE_THREAD);
$server->set([
	'log_file' => '/dev/null',
	'worker_num' => 1,
	'max_request' => 1,
	'heartbeat_check_interval'=> 1,
    'heartbeat_idle_time'=> 2,
]);

$server->on('WorkerStart', function (Swoole\Server $server, $workerId) {
    [$queue] = Thread::getArguments();
    $queue->push('start', Queue::NOTIFY_ALL);
    Timer::after(5000, function () use ($server) {
        $server->shutdown();
    });
});

$server->addProcess(new Swoole\Process(function ($process) use ($server, $port) {
	[$queue] = Thread::getArguments();
	Assert::true($queue->pop(-1) == 'start');
	Assert::true(file_get_contents("http://127.0.0.1:{$port}/") == 'OK');
}));

$server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
    $response->end('OK');
});
$server->start();
?>
--EXPECT--
