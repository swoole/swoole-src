--TEST--
swoole_server/single_thread: heartbeat
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    Assert::isEmpty(@file_get_contents('http://127.0.0.1:' . $pm->getFreePort() . '/'));
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('0.0.0.0', $pm->getFreePort(), SWOOLE_PROCESS);
    $http->set([
        'single_thread' => true,
        'worker_num' => 1,
        'heartbeat_idle_time' => 1,
        'heartbeat_check_interval' => 1,
    ]);
    $http->on('WorkerStart', function (Swoole\Http\Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $http->on('Request', function ($request, $response) use ($http) {
        sleep(3);
        Assert::false($response->end('hello'));
        Assert::eq($http->getLastError(), SWOOLE_ERROR_SESSION_NOT_EXIST);
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
