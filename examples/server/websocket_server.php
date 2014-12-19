<?php
$http = new swoole_http_server("127.0.0.1", 9501);
$http->set(['worker_num' => 4]);
/*
$http->on('open', function($response) {  //handshake成功之后回调, 和js的onopen对应
    echo "handshake success";
    var_dump($response);
});


$http->on('handshake', function($request, $response) {  //自定定握手规则，没有设置则用系统内置的（只支持version:13的）
    if (!isset($request->header['sec-websocket-key'])) {
        //'Bad protocol implementation: it is not RFC6455.'
        $response->end();
        return false;
    }
    if (0 === preg_match('#^[+/0-9A-Za-z]{21}[AQgw]==$#', $request->header['sec-websocket-key']) || 16 !== strlen(base64_decode($request->header['sec-websocket-key']))) {
        //Header Sec-WebSocket-Key is illegal;
        $response->end();
        return false;
    }
    $headers =  array(
        'Upgrade' => 'websocket',
        'Connection' => 'Upgrade',
        'Sec-WebSocket-Accept' => ''. base64_encode(sha1($request->header['sec-websocket-key'] . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true)),
        'Sec-WebSocket-Version' => '13',
        'KeepAlive' => 'off',
    );
    foreach($headers as $key => $val) {
        $response->header($key, $val);
    }
    $response->status(101);
    $response->end();
});
*/

$http->on('message', function($response){
    //var_dump($response);
    //echo "fd:".$response->fd . "fin:".$response->fin . "opcode:".$response->opcode
    $response->message("server send:".$response->data);
});

$http->on('request', function ($request, $response) {
    var_dump($request);
	$response->end("<h1>Hello Swoole. #".rand(1000, 9999)."</h1>");
});

$http->on('close', function(){
    echo "on close\n";
});


$http->start();
