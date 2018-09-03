--TEST--
swoole_http_client_coro: websocket client & server
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
require_once __DIR__ . '/../include/lib/curl.php';

$pm = new ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    go(function () {
        $cli = new Co\http\Client('127.0.0.1', 9501);
        $ret = $cli->upgrade('/');

        if (!$ret)
        {
            echo "ERROR\n";
            return;
        }
        echo $cli->recv()->data;
        $cli->push('hello server');
        
        assert($cli->recv() == false);
        assert($cli->errCode == SOCKET_ETIMEDOUT);
        $cli->errCode = 0;

        assert($cli->recv() == false);
        assert($cli->errCode == SOCKET_ETIMEDOUT);
    });
    swoole_event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $ws = new swoole_websocket_server('127.0.0.1', 9501, SWOOLE_BASE);
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
