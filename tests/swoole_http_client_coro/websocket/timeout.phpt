--TEST--
swoole_http_client_coro/websocket: websocket client & server
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $cli = new Co\http\Client('127.0.0.1', $pm->getFreePort());
        $ret = $cli->upgrade('/');

        if (!$ret)
        {
            echo "ERROR\n";
            return;
        }
        echo $cli->recv()->data;
        $cli->push('hello server');

        Assert::false($cli->recv(.1));
        Assert::same($cli->errCode, SOCKET_ETIMEDOUT);
        $cli->errCode = 0;

        Assert::false($cli->recv(.1));
        Assert::same($cli->errCode, SOCKET_ETIMEDOUT);
    });
    swoole_event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $ws = new swoole_websocket_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $ws->set(array(
        'log_file' => '/dev/null'
    ));
    $ws->on('WorkerStart', function (\swoole_server $serv) {
        /**
         * @var $pm ProcessManager
         */
        global $pm;
        $pm->wakeup();
    });

    $ws->on('open', function ($serv, swoole_http_request $request) {
        $serv->push($request->fd, "start\n");
    });

    $ws->on('message', function ($serv, $frame) {

    });

    $ws->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
start
