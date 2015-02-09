<?php
$http = new swoole_http_server("0.0.0.0", 9502);
$http->set(['worker_num' => 4, 'user'=>'www', 'group'=>'www', 'daemonize'=>0]);

$http->on('open', function($response) {  //handshake成功之后回调, 和js的onopen对应
    echo "handshake success\n";
    var_dump($response);
});

$http->on('message', function(swoole_websocket_frame $frame) use ($http) {
    //var_dump($frame);
    echo "fd:".$frame->fd . ", fin:".$frame->fin . ", opcode:".$frame->opcode."\n";
    $frame->message("server send:".$frame->data);
    //$http->push($frame->fd, "hello, i am swoole http server.");
});

$http->on('request', function ($request, swoole_http_response $response) {
    $response->header('Content-Type', 'text/html; charset=utf-8');
	$response->end(<<<HTML
<!doctype html>
<html>
	<head>
	    <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
		<title>swoole websocket demo ...</title>
	</head>
	<body>
		<script type="text/javascript">
			var ws  = new WebSocket("ws://127.0.0.1:9501");
			ws.onopen = function(){
                console.log("连接服务器成功");
                ws.send("i client");
            };
			ws.onmessage = function(e) {
                console.log("From Server: "+e.data);
            };
			ws.onclose = function(){
                console.log("服务器已关闭");
            };
		</script>

	</body>
</html>
HTML
);
});

$http->on('close', function(){
    echo "on close\n";
});

/*
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

$http->start();
