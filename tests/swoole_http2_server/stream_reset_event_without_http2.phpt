--TEST--
swoole_http2_server: warn when the streamReset callback is set on a port without HTTP/2
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$cases = [
    // The server has no HTTP/2 port.
    'http1 server' => function (Swoole\Http\Server $server) {
        $server->on('StreamReset', function () {});
    },
    // A plain TCP port uses the HTTP/2 primary port's callback only through fallback.
    'http2 primary with tcp port' => function (Swoole\Http\Server $server) {
        $server->set(['open_http2_protocol' => true]);
        $port = $server->listen('127.0.0.1', get_one_free_port(), SWOOLE_SOCK_TCP);
        $port->set(['open_http_protocol' => false]);
        $port->on('Receive', function () {});
        $server->on('StreamReset', function () {});
    },
    // The primary port's callback serves the HTTP/2 secondary port.
    'http2 secondary port' => function (Swoole\Http\Server $server) {
        $server->on('StreamReset', function () {});
        $port = $server->listen('127.0.0.1', get_one_free_port(), SWOOLE_SOCK_TCP);
        $port->set(['open_http2_protocol' => true]);
    },
    // A callback registered on the plain TCP port itself is never called.
    'callback on tcp port' => function (Swoole\Http\Server $server) {
        $server->set(['open_http2_protocol' => true]);
        $port = $server->listen('127.0.0.1', get_one_free_port(), SWOOLE_SOCK_TCP);
        $port->set(['open_http_protocol' => false]);
        $port->on('Receive', function () {});
        $port->on('StreamReset', function () {});
    },
];

foreach ($cases as $name => $configure) {
    $pm = new ProcessManager;
    $pm->parentFunc = function () use ($pm) {
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $name, $configure) {
        echo "{$name}\n";
        $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
        $server->set(['log_file' => '/dev/null']);
        $server->on('Request', function () {});
        $server->on('WorkerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $configure($server);
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
?>
--EXPECTF--
http1 server

Warning: Swoole\Server::start(): port[127.0.0.1:%d] sets the streamReset callback without open_http2_protocol in %s on line %d
http2 primary with tcp port
http2 secondary port
callback on tcp port

Warning: Swoole\Server::start(): port[127.0.0.1:%d] sets the streamReset callback without open_http2_protocol in %s on line %d
