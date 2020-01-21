--TEST--
swoole_server_port: sub server use websocket and handshake
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->initFreePorts(2);
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort(1));
        $cli->set(['timeout' => 5]);
        $ret = $cli->upgrade('/');
        Assert::assert($ret);
        $cli->push('Hello~');
        $ret = $cli->recv();
        var_dump($ret);
    });
    swoole_event_wait();
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $main_server = new swoole_http_server('127.0.0.1', $pm->getFreePort(0), SWOOLE_BASE);
    $main_server->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        $response->write('hello world');
        $response->end();
    });
    $sub_server = $main_server->listen('127.0.0.1', $pm->getFreePort(1), SWOOLE_SOCK_TCP);
    $sub_server->set([
        'open_http_protocol' => true,
        'open_websocket_protocol' => true
    ]);
    $sub_server->on('handshake', function (swoole_http_request $request, swoole_http_response $response) {
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
            'Sec-WebSocket-Version' => '13'
        ];
        // failed: Error during WebSocket handshake:
        // Response must not include 'Sec-WebSocket-Protocol' header if not present in request: websocket
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
    $sub_server->on('message', function (swoole_http_server $server, swoole_websocket_frame $frame) {
        var_dump($frame);
        $response = new swoole_websocket_frame;
        $response->data = 'OK';
        $server->send($frame->fd, (string)$response);
    });
    $main_server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
object(Swoole\WebSocket\Frame)#%d (5) {
  ["fd"]=>
  int(1)
  ["data"]=>
  string(6) "Hello~"
  ["opcode"]=>
  int(1)
  ["flags"]=>
  int(%d)
  ["finish"]=>
  bool(true)
}
object(Swoole\WebSocket\Frame)#%d (5) {
  ["fd"]=>
  int(%d)
  ["data"]=>
  string(2) "OK"
  ["opcode"]=>
  int(1)
  ["flags"]=>
  int(%d)
  ["finish"]=>
  bool(true)
}
