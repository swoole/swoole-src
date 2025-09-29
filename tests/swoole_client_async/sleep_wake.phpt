--TEST--
swoole_client_async: Swoole\Async\Client sleep & sleep
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    $cli = new \Swoole\Async\Client(SWOOLE_SOCK_TCP);

    $cli->on("connect", function (Swoole\Async\Client $cli) {
        Assert::true($cli->isConnected());
        $r = $cli->sleep();
        Assert::assert($r);
        swoole_timer_after(200, function () use ($cli) {
            $r = $cli->wakeup();
            Assert::assert($r);
        });
        $cli->send(RandStr::gen(1024, RandStr::ALL));
    });

    $cli->on("receive", function (Swoole\Async\Client $cli, $data) {
        $recv_len = strlen($data);
        $cli->send(RandStr::gen(1024, RandStr::ALL));
        $cli->close();
        Assert::false($cli->isConnected());
    });

    $cli->on("error", function (Swoole\Async\Client $cli) {
        echo "error";
    });

    $cli->on("close", function (Swoole\Async\Client $cli) {
        echo "SUCCESS";
    });

    $cli->connect('127.0.0.1', $pm->getFreePort(), 0.1);
    Swoole\Event::wait();
    Swoole\Process::kill($pid);
};

$pm->childFunc = function () use ($pm) {
    include __DIR__ . "/../include/api/tcp_server.php";
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
