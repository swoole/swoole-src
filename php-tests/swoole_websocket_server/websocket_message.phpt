--TEST--
Test of swoole_http_client websocket push
--SKIPIF--
<?php include "skipif.inc"; ?>
--FILE--
<?php
include "include.inc";

function start_swoole_ws_server() {
	$code = <<<'DOC'
        $serv = new swoole_websocket_server("127.0.0.1", 9501);

        $serv->on('Open', function($server, $req) {
        });

        $serv->on('Message', function($server, $frame) {
            $server->push($frame->fd, "hello " . $frame->data);
        });

        $serv->on('Close', function($server, $fd) {
        });

        $serv->start();
DOC;
	
	swoole_php_fork($code);
}
sleep(1);	//wait the release of port 9501
start_swoole_ws_server();
sleep(1);

$cli = new WebsocketClient;
$connected = $cli->connect('127.0.0.1', 9501, '/');
echo $cli->sendData("batman"), "\r\n";
echo $cli->sendData("spiderman"), "\r\n";
?>
Done
--EXPECTREGEX--
hello batman
hello spiderman
Done.*
--CLEAN--
