--TEST--
swoole_timer: timer round control
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use($pm)
{
    $cli = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_ASYNC);

    $cli->on("connect", function(swoole_client $cli) {
        $cli->send("hello\n");
        $cli->timer = swoole_timer_after(1, function () use ($cli) {
            echo "TIMEOUT\n";
            $cli->close();
        });
        usleep(2000);
    });

    $cli->on("receive", function (swoole_client $cli, $data) {
        swoole_timer_clear($cli->timer);
        echo $data;
        $cli->close();
    });

    $cli->on("error", function(swoole_client $cli) {
        echo "ERROR\n";
    });

    $cli->on("close", function(swoole_client $cli) {
        echo "CLOSE\n";
    });

    $cli->connect(TCP_SERVER_HOST, $pm->getFreePort(), 0.2);
    swoole_event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $serv = new swoole_server('127.0.0.1',  $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(array(
        'log_file' => TEST_LOG_FILE,
    ));
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data)
    {
        $serv->send($fd, "hello world\n");
    });
    $serv->start();
};
$pm->async = true;
$pm->childFirst();
$pm->run();
?>
--EXPECT--
hello world
CLOSE
