--TEST--
swoole_server: bug aio
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
define('__FILE_CONTENTS__', file_get_contents(__FILE__));
$pm = new SwooleTest\ProcessManager;
$pm->setWaitTimeout(0);
$pm->parentFunc = function () {
};
$pm->childFunc = function () use ($pm) {
    go(function () {
        Assert::same(Co::readFile(__FILE__), __FILE_CONTENTS__); // will be discarded
    });
    Swoole\Event::wait();
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS);
    $server->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $server->on('WorkerStart', function (Swoole\Server $server, int $worker_id) use ($pm) {
        echo 'read file' . PHP_EOL;
        Assert::same(Co::readFile(__FILE__), __FILE_CONTENTS__);
        echo 'read file ok' . PHP_EOL;
        $pm->wakeup();
        usleep(100000);
        $server->shutdown();
    });
    $server->on('Receive', function () {
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
read file
read file ok
