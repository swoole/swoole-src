--TEST--
swoole_websocket_server: websocket server disconnect
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
        $serv = new swoole_websocket_server("127.0.0.1", 9501);
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

$response = $cli->sendRecv("shutdown");

$byteArray = unpack('C*', $response);

assert($byteArray[1] == 0x0F);	// Test Status Code bit 1 = 15
assert($byteArray[2] == 0xA0);  // Test Status Code bit 2 = 160

echo $byteArray[1]."\n";
echo $byteArray[2]."\n";
echo substr($response, 2);

?>

--EXPECT--
15
160
shutdown received
--CLEAN--
