--TEST--
swoole_http_client: websocket push 3
--SKIPIF--
<?php require __DIR__ . "/../include/skipif.inc"; ?>
--INI--
assert.active=1
assert.warning=1
assert.bail=0
assert.quiet_eval=0

--FILE--
<?php
require __DIR__ . "/../include/swoole.inc";
require __DIR__ . "/../include/lib/class.websocket_client.php";

function start_swoole_ws_server() {
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
            sleep(1);
            $swoole_server->push($frame->fd, "hello " . $frame->data . " again");
        });

        $serv->on('Close', function ($swoole_server, $fd)
        {
        });

        $serv->start();
    });
}
sleep(1);	//wait the release of port 9501
start_swoole_ws_server();
sleep(1);

$cli = new WebsocketClient;
$connected = $cli->connect('127.0.0.1', 9501, '/');
echo $cli->sendRecv("batman"), "\r\n";
sleep(2);
echo $cli->recvData(), "\r\n";
?>
Done
--EXPECTREGEX--
hello batman
hello batman again
Done.*
--CLEAN--
