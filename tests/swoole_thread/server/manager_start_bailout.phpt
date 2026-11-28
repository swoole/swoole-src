--TEST--
swoole_thread/server: manager startup bailout still stops and joins its workers
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_nts();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Thread;

$serv = new Swoole\Server('127.0.0.1', get_constant_port(__FILE__), SWOOLE_THREAD);
$serv->set([
    'worker_num' => 1,
    'log_file' => '/dev/null',
    'init_arguments' => function () {
        global $exited;
        $exited = new Thread\Atomic(0);
        return [$exited];
    },
]);
$serv->on('WorkerStart', function () {
    [$exited] = Thread::getArguments();
    register_shutdown_function(function () use ($exited) {
        $exited->add();
    });
});
$serv->on('ManagerStart', function () {
    swoole_implicit_fn('bailout', 237);
});
$serv->on('ManagerStop', function () {
    echo "unexpected ManagerStop\n";
});
$serv->on('BeforeShutdown', function () {
    echo "before shutdown\n";
});
$serv->on('Shutdown', function () {
    global $exited;
    Assert::same($exited->get(), 1);
    Assert::same(Thread::activeCount(), 1);
    echo "DONE\n";
});
$serv->on('Receive', function () {});
$serv->start();
?>
--EXPECT--
before shutdown
DONE
