<?php
// Broadcast each message to every connected WebSocket client.
// Run: php examples/websocket/broadcast.php (connect a WebSocket client to 9502)
$server = new Swoole\WebSocket\Server('127.0.0.1', 9502);
$server->on('open', function ($server, $request) {
    echo "client {$request->fd} connected" . PHP_EOL;
});
$server->on('message', function ($server, $frame) {
    foreach ($server->connections as $fd) {
        if ($server->isEstablished($fd)) {
            $server->push($fd, "client {$frame->fd} said: {$frame->data}");
        }
    }
});
$server->on('close', function ($server, $fd) {
    echo "client $fd closed" . PHP_EOL;
});
$server->start();
