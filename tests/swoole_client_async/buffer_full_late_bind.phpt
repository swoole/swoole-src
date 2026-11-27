--TEST--
swoole_client_async: bufferFull registered after connect is effective
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
error_reporting(E_ALL & ~E_DEPRECATED);

// The peer accepts the connection but never reads, so the output buffer fills up.
$server = stream_socket_server('tcp://127.0.0.1:0');
$port = (int) substr(strrchr(stream_socket_get_name($server, false), ':'), 1);

$cli = new Swoole\Async\Client(SWOOLE_SOCK_TCP);
$cli->on('receive', function () {});
$cli->on('error', function () { echo "error\n"; });
$cli->on('close', function () { echo "close\n"; });
$cli->on('connect', function (Swoole\Async\Client $cli) {
    $cli->on('bufferFull', function (Swoole\Async\Client $cli) {
        echo "full\n";
        $cli->close();
    });
    for ($i = 0; $i < 4096 && $cli->isConnected(); $i++) {
        if ($cli->send(str_repeat('A', 65536)) === false) {
            break;
        }
    }
});
$cli->connect('127.0.0.1', $port);
Swoole\Event::wait();
?>
--EXPECT--
full
close
