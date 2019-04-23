--TEST--
swoole_client_async: swoole_client sleep & sleep
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    $cli = new \swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

    $cli->on("connect", function (swoole_client $cli)
    {
        Assert::true($cli->isConnected());
        $r = $cli->sleep();
        Assert::assert($r);
        swoole_timer_after(200, function () use ($cli)
        {
            $r = $cli->wakeup();
            Assert::assert($r);
        });
        $cli->send(RandStr::gen(1024, RandStr::ALL));
    });

    $cli->on("receive", function(swoole_client $cli, $data){
        $recv_len = strlen($data);
        $cli->send(RandStr::gen(1024, RandStr::ALL));
        $cli->close();
        Assert::false($cli->isConnected());
    });

    $cli->on("error", function(swoole_client $cli) {
        echo "error";
    });

    $cli->on("close", function(swoole_client $cli) {
        echo "SUCCESS";
    });

    $cli->connect('127.0.0.1', $pm->getFreePort(), 0.1);
    swoole_event::wait();
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    include __DIR__ . "/../include/api/tcp_server.php";
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS