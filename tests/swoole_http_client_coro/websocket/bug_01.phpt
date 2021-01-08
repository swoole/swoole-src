--TEST--
swoole_http_client_coro/websocket: handshake + frame
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
        echo "CONNECTED\n";
        echo $cli->recv()->data;
    });
    swoole_event::wait();
    $pm->kill();
};

$pm->childFunc = function () use ($pm)
{
    $ws = new swoole_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
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

    $ws->on('receive', function ($serv, $fd, $threadId, $data) {
        $sendData = "HTTP/1.1 101 Switching Protocols\r\n";
        $sendData .= "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-Websocket-Accept: IFpdKwYy9wdo4gTldFLHFh3xQE0=\r\n";
        $sendData .= "Sec-Websocket-Version: 13\r\nServer: swoole-http-server\r\n\r\n";
        $sendData .= swoole_websocket_server::pack("hello world\n");
        $serv->send($fd, $sendData);
    });

    $ws->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
CONNECTED
hello world
