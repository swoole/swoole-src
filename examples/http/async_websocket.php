<?php
$cli = new swoole_http_client('127.0.0.1', 9501);
//post request
//$cli->setData(http_build_query(['a'=>123,'b'=>"哈哈"]));
$cli->setHeaders([
    'Connection' => "Upgrade",
    'Upgrade' => 'websocket',
    'Sec-WebSocket-Key' => '1ZHQOHNfAXBMEUF2yuh1Sg==',
    'Sec-WebSocket-Extensions' => 'permessage-deflate; client_max_window_bits',
]);

$cli->on('message', function ($_cli, $frame) {
    var_dump($frame);
});

$cli->execute('/', function ($cli)
{
    echo $cli->body;
    $cli->push("hello world");
});

