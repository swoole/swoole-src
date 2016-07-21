<?php
//$server = new swoole_websocket_server("0.0.0.0", 9501);
$server = new swoole_websocket_server("0.0.0.0", 9501, SWOOLE_BASE);
//$server->addlistener('0.0.0.0', 9502, SWOOLE_SOCK_UDP);
//$server->set(['worker_num' => 4,
//    'task_worker_num' => 4,
//]);

function user_handshake(swoole_http_request $request, swoole_http_response $response)
{
    //自定定握手规则，没有设置则用系统内置的（只支持version:13的）
    if (!isset($request->header['sec-websocket-key']))
    {
        //'Bad protocol implementation: it is not RFC6455.'
        $response->end();
        return false;
    }
    if (0 === preg_match('#^[+/0-9A-Za-z]{21}[AQgw]==$#', $request->header['sec-websocket-key'])
        || 16 !== strlen(base64_decode($request->header['sec-websocket-key']))
    )
    {
        //Header Sec-WebSocket-Key is illegal;
        $response->end();
        return false;
    }

    $key = base64_encode(sha1($request->header['sec-websocket-key']
        . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11',
        true));
    $headers = array(
        'Upgrade'               => 'websocket',
        'Connection'            => 'Upgrade',
        'Sec-WebSocket-Accept'  => $key,
        'Sec-WebSocket-Version' => '13',
        'KeepAlive'             => 'off',
    );
    foreach ($headers as $key => $val)
    {
        $response->header($key, $val);
    }
    $response->status(101);
    $response->end();
    global $server;
    $fd = $request->fd;
    $server->defer(function () use ($fd, $server)
    {
        $server->push($fd, "hello, welcome\n");
    });
    return true;
}

$server->on('handshake', 'user_handshake');
$server->on('open', function (swoole_websocket_server $_server, swoole_http_request $request) {
    echo "server#{$_server->worker_pid}: handshake success with fd#{$request->fd}\n";
    var_dump($_server->exist($request->fd), $_server->getClientInfo($request->fd));
//    var_dump($request);
});

$server->on('message', function (swoole_websocket_server $_server, $frame) {
    var_dump($frame->data);
    echo "received ".strlen($frame->data)." bytes\n";
    if ($frame->data == "close")
    {
        $_server->close($frame->fd);
    }
    elseif($frame->data == "task")
    {
        $_server->task(['go' => 'die']);
    }
    else
    {
        //echo "receive from {$frame->fd}:{$frame->data}, opcode:{$frame->opcode}, finish:{$frame->finish}\n";
       // for ($i = 0; $i < 100; $i++)
        {
            $_send = str_repeat('B', rand(100, 800));
            $_server->push($frame->fd, $_send);
           // echo "#$i\tserver sent " . strlen($_send) . " byte \n";
        }
        $fd = $frame->fd;
        $_server->tick(2000, function($id) use ($fd, $_server) {
            $_send = str_repeat('B', rand(100, 5000));
            $ret = $_server->push($fd, $_send);
            if (!$ret)
            {
                var_dump($id);
                var_dump($_server->clearTimer($id));
            }
        });
    }
});

$server->on('close', function ($_server, $fd) {
    echo "client {$fd} closed\n";
});

$server->on('task', function ($_server, $worker_id, $task_id, $data)
{
    var_dump($worker_id, $task_id, $data);
    return "hello world\n";
});

$server->on('finish', function ($_server, $task_id, $result)
{
    var_dump($task_id, $result);
});

$server->on('packet', function ($_server, $data, $client) {
    echo "#".posix_getpid()."\tPacket {$data}\n";
    var_dump($client);
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
