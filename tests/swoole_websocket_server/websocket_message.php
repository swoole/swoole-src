<?php
require_once __DIR__ . "/../include/swoole.inc";
include __DIR__ . "/../include/lib/class.websocket_client.php";

function start_swoole_ws_server()
{
    swoole_php_fork(function ()
    {
        $serv = new swoole_websocket_server("127.0.0.1", 9501);
        $serv->set(['log_file' => '/dev/null']);
        $serv->on('Open', function ($swoole_server, $req)
        {
        });
        $serv->on('Message', function ($swoole_server, $frame)
        {
            $swoole_server->push($frame->fd, "hello " . $frame->data);
            if ($frame->data == "shutdown")
            {
                $swoole_server->shutdown();
            }
        });
        $serv->on('Close', function ($swoole_server, $fd)
        {
        });
        $serv->start();
    });
}

sleep(1);    //wait the release of port 9501
start_swoole_ws_server();
sleep(1);

$cli = new WebsocketClient;
$connected = $cli->connect('127.0.0.1', 9501, '/');
assert($connected);
assert($cli->sendRecv("batman") == 'hello batman');
assert($cli->sendRecv("spiderman") == 'hello spiderman');
?>

