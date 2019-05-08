--TEST--
swoole_client_coro: recv after close
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    go(function () use ($pm) {
        $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $cli->connect('127.0.0.1', $pm->getFreePort());

        $cli->send("hello world\n");
        co::sleep(0.2);
        $retData = $cli->recv();
        Assert::assert($retData === false);
        Assert::assert($cli->errCode === SOCKET_ECONNRESET);
        $cli->close();
        Assert::assert(!$cli->connected);
    });
    swoole_event_wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set([
        'worker_num' => 1,
        //'dispatch_mode'         => 1,
        'log_file' => '/dev/null',
        'open_length_check' => true,
        'package_max_length' => 1024 * 1024,
        'package_length_type' => 'N',
        'package_length_offset' => 0,
        'package_body_offset' => 4,
    ]);
    $serv->on("WorkerStart", function (\swoole_server $serv)  use ($pm)
    {
        $pm->wakeup();
    });
    $serv->on('receive', function (swoole_server $serv, $fd, $rid, $data)
    {
        $serv->close($fd);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
