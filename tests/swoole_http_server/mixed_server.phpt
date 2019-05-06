--TEST--
swoole_http_server: http mixed server
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_http2();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$tcp_options = [
    'open_length_check' => true,
    'package_length_type' => 'n',
    'package_length_offset' => 0,
    'package_body_offset' => 2,
];

$pm = new ProcessManager;
$pm->initFreePorts(2);
// client side
$pm->parentFunc = function ($pid) use ($pm, $tcp_options) {
    go(function () use ($pm, $tcp_options) {
        // http
        $http_client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort(0));
        Assert::assert($http_client->post('/', 'Swoole Http'));
        var_dump($http_client->body);

        // http2
        $http2_client = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort(0));
        $http2_client->connect();
        $http2_request = new swoole_http2_request;
        $http2_request->method = 'POST';
        $http2_request->data = 'Swoole Http2';
        $http2_client->send($http2_request);
        $http2_response = $http2_client->recv();
        var_dump($http2_response->data);

        // websocket
        $http_client->upgrade('/');
        $http_client->push('Swoole Websocket');
        var_dump($http_client->recv()->data);

        // tcp
        $tcp_client = new Swoole\Coroutine\Client(SWOOLE_TCP);
        $tcp_client->set($tcp_options);
        $tcp_client->connect('127.0.0.1', $pm->getFreePort(1));
        $tcp_client->send(tcp_pack('Swoole Tcp'));
        var_dump(tcp_unpack($tcp_client->recv()));

        $pm->kill();
    });
};
// server side
$pm->childFunc = function () use ($pm, $tcp_options) {
    $server = new swoole_websocket_server('127.0.0.1', $pm->getFreePort(0), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true
    ]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    // http && http2
    $server->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        $response->end('Hello ' . $request->rawcontent());
    });
    // websocket
    $server->on('message', function (swoole_websocket_server $server, swoole_websocket_frame $frame) {
        $server->push($frame->fd, 'Hello ' . $frame->data);
    });
    // tcp
    $tcp_server = $server->listen('127.0.0.1', $pm->getFreePort(1), SWOOLE_TCP);
    $tcp_server->set($tcp_options);
    $tcp_server->on('receive', function (swoole_server $server, int $fd, int $reactor_id, string $data) {
        $server->send($fd, tcp_pack('Hello ' . tcp_unpack($data)));
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
string(17) "Hello Swoole Http"
string(18) "Hello Swoole Http2"
string(22) "Hello Swoole Websocket"
string(16) "Hello Swoole Tcp"
