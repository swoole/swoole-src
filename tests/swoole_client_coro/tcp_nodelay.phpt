--TEST--
swoole_client_coro: tcp client
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->initFreePorts(2);

$pm->parentFunc = function ($pid) use ($pm)
{
    go(function () use ($pm) {
        echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
        $pm->kill();
    });
};

$pm->childFunc = function () use ($pm)
{
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(0), SWOOLE_BASE);

    $port2 = $http->listen('127.0.0.1', $pm->getFreePort(1), SWOOLE_SOCK_TCP);
    $port2->set([]);
    $port2->on('Receive', function ($serv, $fd, $rid, $data)
    {
        $serv->send($fd, "Swoole: $data");
    });

    $http->set(array(
        'log_file' => '/dev/null'
    ));
    $http->on("WorkerStart", function (\swoole_server $serv)
    {
        /**
         * @var $pm ProcessManager
         */
        global $pm;
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) use ($pm)
    {
        $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $cli->set(['open_tcp_nodelay' => false]);
        if (!$cli->connect('127.0.0.1', $pm->getFreePort(1)))
        {
            fail:
            $response->end("ERROR\n");
            return;
        }
        if (!$cli->send("hello"))
        {
            goto fail;
        }
        $ret = $cli->recv();
        if (!$ret)
        {
            goto fail;
        }
        $response->end("OK\n");
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
