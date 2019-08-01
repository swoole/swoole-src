<?php
//$server = new swoole_websocket_server("0.0.0.0", 9502);
$server = new swoole_websocket_server("0.0.0.0", 9502, SWOOLE_BASE);
$server->set(['worker_num' => 4]);
//
//$server->on('open', function (swoole_websocket_server $_server, swoole_http_request $request) {
//    //echo "server#{$_server->worker_pid}: handshake success with fd#{$request->fd}\n";
//
////    var_dump($request);
//});

$server->on('message', function (swoole_websocket_server $_server, $frame) {
    //var_dump($frame);
    //echo "received ".strlen($frame->data)." bytes\n";
    //echo "receive from {$fd}:{$data},opcode:{$opcode},fin:{$fin}\n";
    $_server->push($frame->fd, "server:" . $frame->data);
    //	$_server->close($frame->fd);
});

//$server->on('close', function ($_server, $fd) {
//    echo "client {$fd} closed\n";
//});


$server->start();
