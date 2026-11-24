<?php
// Connect to a WebSocket server, send a frame and read the reply.
// Start examples/websocket/broadcast.php first, then run this.
// Run: php examples/websocket/client_basic.php
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

run(function () {
    $client = new Client('127.0.0.1', 9502);
    if (!$client->upgrade('/')) {
        echo 'start examples/websocket/broadcast.php first' . PHP_EOL;
        return;
    }
    $client->push('hello');
    $frame = $client->recv();
    echo $frame ? $frame->data : 'no frame received', PHP_EOL;
    $client->close();
});
