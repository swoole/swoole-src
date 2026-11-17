--TEST--
swoole_thread/server: a user worker is still restarted before shutdown is requested
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
        global $starts, $ready;
        $starts = new Thread\Atomic(0);
        $ready = new Thread\Atomic(0);
        return [$starts, $ready];
    },
]);
$serv->on('Start', function () {
    global $ready;
    $ready->set(1);
});
$serv->on('Receive', function () {});
$serv->on('Shutdown', function () {
    global $starts;
    Assert::true($starts->get() > 1);
    echo "user worker restarted\n";
});
$serv->addProcess(new Swoole\Process(function () {
    global $serv;
    [$starts, $ready] = Thread::getArguments();
    if ($starts->add() !== 2) {
        return;
    }
    while ($ready->get() === 0) {
        usleep(1000);
    }
    Assert::true($serv->shutdown());
}));
$serv->start();
?>
--EXPECT--
user worker restarted
