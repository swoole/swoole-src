--TEST--
swoole_thread/server: bind event workers to available CPUs
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
skip('no thread affinity', !method_exists(Swoole\Thread::class, 'getAffinity'));
$affinity = Swoole\Thread::getAffinity();
skip('requires CPUs 0 and 1', !in_array(0, $affinity) || !in_array(1, $affinity));
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Thread;
use Swoole\Thread\Queue;

$port = get_constant_port(__FILE__);
$server = new Swoole\Http\Server('127.0.0.1', $port, SWOOLE_THREAD);
$server->set(array(
    'worker_num' => 1,
    'open_cpu_affinity' => true,
    'cpu_affinity_ignore' => array(0),
    'log_level' => SWOOLE_LOG_ERROR,
    'init_arguments' => function () {
        return [new Queue()];
    },
));
$server->on('WorkerStart', function () {
    [$queue] = Thread::getArguments();
    echo implode(',', Thread::getAffinity()), PHP_EOL;
    $queue->push(true, Queue::NOTIFY_ALL);
});
$server->on('Request', function ($request, $response) {
    $response->end('OK');
});
$server->addProcess(new Swoole\Process(function () use ($server, $port) {
    [$queue] = Thread::getArguments();
    $queue->pop(-1);
    Assert::eq(file_get_contents("http://127.0.0.1:{$port}/"), 'OK');
    $server->shutdown();
}));
$server->start();
?>
--EXPECT--
1
