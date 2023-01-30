--TEST--
swoole_http_client_coro/websocket: close socket
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
        if (!$ret) {
            echo "ERROR\n";
            return;
        }
        Assert::assert($cli->socket->close());
        Assert::false($cli->recv());
        Assert::eq($cli->errCode, SWOOLE_ERROR_CLIENT_NO_CONNECTION);
        Assert::false($cli->push('hello server'));
        Assert::eq($cli->errCode, SWOOLE_ERROR_CLIENT_NO_CONNECTION);
    });
    Swoole\Event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $ws = new Swoole\WebSocket\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $ws->set(array(
        'log_file' => '/dev/null'
    ));
    $ws->on('WorkerStart', function (Swoole\Server $serv) {
        global $pm;
        $pm->wakeup();
    });
    $ws->on('open', function ($serv, Swoole\Http\Request $request) {

    });
    $ws->on('message', function ($serv, $frame) {
        $serv->push($frame->fd, "hello client\n");
    });
    $ws->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
