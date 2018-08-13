--TEST--
swoole_websocket_server: websocket server active close with code, reason
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>

--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
include __DIR__ . "/../include/lib/class.websocket_client.php";

function start_swoole_ws_server()
{
    swoole_php_fork(function ()
    {
        $serv = new swoole_websocket_server("127.0.0.1", PORT);
        $serv->set(['log_file' => '/dev/null']);
        $serv->on('Open', function ($swoole_server, $req)
        {
        });
        $serv->on('Message', function ($swoole_server, $frame)
        {
            if ($frame->data == "shutdown")
            {
                $swoole_server->disconnect($frame->fd, 4000, "shutdown received");
            }
        });
        $serv->on('websocketclose', function ($swoole_server, $code, $reason)
        {
            echo $code."\n";
            echo $reason."\n";
        });
        $serv->on('Close', function ($swoole_server, $fd)
        {
        });
        $serv->start();
    });
    sleep(1);   // Wait for opening of server
}

define("PORT", get_one_free_port());
start_swoole_ws_server();

$cli = new WebsocketClient;
$connected = $cli->connect('127.0.0.1', PORT, '/');
assert($connected);

$response = $cli->sendRecv("shutdown");

?>

--EXPECT--
4000
shutdown received
--CLEAN--
