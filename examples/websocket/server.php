<?php
$server = new swoole_websocket_server("0.0.0.0", 9501);

$server->set(['worker_num' => 1]);

$server->on('open', function (swoole_websocket_server $server, $fd, $request) {
    echo "server: handshake success with fd{$fd}\n";
//    var_dump($request);
});

$server->on('message', function (swoole_websocket_server $server, $fd, $data, $opcode, $fin) {
    echo "received ".strlen($data)." bytes\n";
    //echo "receive from {$fd}:{$data},opcode:{$opcode},fin:{$fin}\n";
    $server->push($fd, "this is server");
});

$server->on('close', function ($ser, $fd) {
    echo "client {$fd} closed\n";
});

$server->on('request', function (swoole_http_request $request, swoole_http_response $response) {
    $response->end(<<<HTML
    <h1>Swoole WebSocket Server</h1>
    <script>
var wsServer = 'ws://127.0.0.1:9501';
var websocket = new WebSocket(wsServer);
websocket.onopen = function (evt) {
	console.log("Connected to WebSocket server.");
};

websocket.onclose = function (evt) {
	console.log("Disconnected");
};

websocket.onmessage = function (evt) {
	console.log('Retrieved data from server: ' + evt.data);
};

websocket.onerror = function (evt, e) {
	console.log('Error occured: ' + evt.data);
};
</script>
HTML
    );
});

$server->start();
