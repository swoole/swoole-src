<?php

Co\Run(function () {
    $server = new Co\Http\Server("127.0.0.1", 9502, false);
    $server->handle('/websocket', function ($request, $ws) {
        $ws->upgrade();
        while (true) {
            $frame = $ws->recv();
            if ($frame === false) {
                echo "error : " . swoole_last_error() . "\n";
                break;
            } else if ($frame == '') {
                break;
            } else {
                if ($frame->data == "close") {
                    $ws->close();
                    return;
                }
                $ws->push("Hello {$frame->data}!");
                $ws->push("How are you, {$frame->data}?");
            }
        }
    });
    
        $server->handle('/', function ($request, $response) {
            $response->end(<<<HTML
    <h1>Swoole WebSocket Server</h1>
    <script>
var wsServer = 'ws://127.0.0.1:9502/websocket';
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
});