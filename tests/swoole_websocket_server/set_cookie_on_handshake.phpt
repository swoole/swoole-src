--TEST--
swoole_websocket_server: websocket server set cookie on handshake (#3270)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->initFreePorts();
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $cli = new Co\Http\Client('127.0.0.1', $pm->getFreePort());
        if (Assert::true($cli->upgrade('/'))) {
            Assert::same($cli->headers['x-asdf'], 'asdf');
            Assert::same($cli->set_cookie_headers, [
                'foo=bar',
                'abc=def'
            ]);
        }
    });
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\WebSocket\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('handshake', function (\Swoole\Http\Request $request, \Swoole\Http\Response $response) {
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
            'Set-Cookie' => 'foo=bar',
            'X-asdf' => 'asdf'
        ];
        // WebSocket connection to 'ws://127.0.0.1:9502/'
        // failed: Error during WebSocket handshake:
        // Response must not include 'Sec-WebSocket-Protocol' header if not present in request: websocket
        if (isset($request->header['sec-websocket-protocol'])) {
            $headers['Sec-WebSocket-Protocol'] = $request->header['sec-websocket-protocol'];
        }
        foreach ($headers as $key => $val) {
            $response->header($key, $val);
        }
        $response->cookie('abc', 'def');
        $response->status(101);
        $response->end();
        return true;
    });
    $server->on('message', function () { });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
