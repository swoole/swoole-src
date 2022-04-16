--TEST--
swoole_websocket_server: websocket compression with handshake
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\WebSocket\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;

$pm = new ProcessManager;
$pm->initFreePorts();
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $cli = new Co\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->setHeaders(['Sec-WebSocket-Extensions' => 'permessage-deflate; client_max_window_bits']);
        if (Assert::true($cli->upgrade('/'))) {
            Assert::contains($cli->headers['sec-websocket-extensions'], 'permessage-deflate');
        }
    });
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['websocket_compression' => true]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    // test with Chrome
    $server->on('request', function (Request $request, Response $response) use ($pm) {
        $port = $pm->getFreePort();
        $response->end(<<<HTML
<script>
var wsServer = 'ws://127.0.0.1:{$port}';
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
HTML);
    });
    $server->on('handshake', function (Request $request, Response $response) {
        $secWebSocketKey = $request->header['sec-websocket-key'];
        $patten = '#^[+/0-9A-Za-z]{21}[AQgw]==$#';
        if (0 === preg_match($patten, $secWebSocketKey) || 16 !== strlen(base64_decode($secWebSocketKey))) {
            $response->end();
            return false;
        }
        $key = base64_encode(sha1(
            $request->header['sec-websocket-key'] . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11',
            true
        ));
        $headers = [
            'Upgrade' => 'websocket',
            'Connection' => 'Upgrade',
            'Sec-WebSocket-Accept' => $key,
            'Sec-WebSocket-Version' => '13',
        ];
        if (isset($request->header['sec-websocket-protocol'])) {
            $headers['Sec-WebSocket-Protocol'] = $request->header['sec-websocket-protocol'];
        }
        foreach ($headers as $key => $val) {
            $response->header($key, $val);
        }
        $response->status(101);
        $response->end();
        return true;
    });
    $server->on('message', function ($serv, $frame) {
        $serv->push($frame->fd, "hello world");
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
