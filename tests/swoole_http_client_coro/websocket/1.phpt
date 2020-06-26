--TEST--
swoole_http_client_coro/websocket: client & server
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $cli = new Co\http\Client('127.0.0.1', $pm->getFreePort());
        $cli->set(['timeout' => -1]);
        $cli->setHeaders([]);
        $ret = $cli->upgrade('/');

        if (!$ret)
        {
            echo "ERROR\n";
            return;
        }
        echo $cli->recv()->data;
        for ($i = 0; $i < 5; $i++)
        {
            $cli->push('hello server');
            echo ($cli->recv())->data;
            co::sleep(0.1);
        }
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
        $ip = co::gethostbyname('www.baidu.com');
        if ($ip)
        {
            $serv->push($request->fd, "start\n");
        }
    });

    $ws->on('message', function ($serv, $frame) {
        co::sleep(0.1);
        $serv->push($frame->fd, "hello client\n");
    });

    $ws->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
start
hello client
hello client
hello client
hello client
hello client
