--TEST--
swoole_http_client: websocket client bug 1015
--SKIPIF--
<?php require  __DIR__ . "/../include/skipif.inc"; ?>
--FILE--
<?php
require_once __DIR__ . "/../include/swoole.inc";
$pm = new ProcessManager;
$pm->parentFunc = function ($pid)
{
    $cli = new swoole_http_client('127.0.0.1', 9501);
    $cli->on('close', function ($cli)
    {
        echo "close\n";
    });
    $cli->on('error', function ($cli)
    {
        echo "error\n";
    });
    $cli->on('Message', function ($cli, $frame)
    {
        echo $frame->data;
        $cli->close();
    });
    $cli->upgrade('/', function ($cli)
    {
        echo "CONNECTED\n";
    });
    swoole_event::wait();
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    $ws = new swoole_server("127.0.0.1", 9501, SWOOLE_BASE);
    $ws->set(array(
        'log_file' => '/dev/null'
    ));
    $ws->on("WorkerStart", function (\swoole_server $serv) {
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
close
