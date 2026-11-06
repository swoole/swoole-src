--TEST--
swoole_client_async: a sendfile that fails closes the connection
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_linux();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Async\Client;

$pm             = new ProcessManager();
$pm->parentFunc = function () use ($pm) {
    $client = new Client(SWOOLE_SOCK_TCP);
    $client->set(['buffer_high_watermark' => 1024]);
    $client->on('connect', function (Client $client) {
        // A directory opens and has a size, but sendfile() rejects it with EINVAL.
        Assert::true($client->sendfile(__DIR__));
        Assert::same($client->send(str_repeat('a', 4096)), 4096);
    });
    $client->on('receive', function () {});
    $client->on('error', function () {
        echo "error\n";
    });
    $client->on('bufferFull', function () {
        echo "buffer full\n";
    });
    $client->on('bufferEmpty', function () {
        echo "buffer empty\n";
    });
    $client->on('close', function () {
        echo "close\n";
    });
    $client->connect('127.0.0.1', $pm->getFreePort(), 1);
    Swoole\Event::wait();
};
$pm->childFunc = function () use ($pm) {
    $server = stream_socket_server('tcp://127.0.0.1:' . $pm->getFreePort());
    $pm->wakeup();
    $conn = stream_socket_accept($server, 5);
    stream_set_timeout($conn, 5);
    // Nothing queued after the failed file may reach the peer.
    Assert::same(stream_get_contents($conn), '');
    Assert::false(stream_get_meta_data($conn)['timed_out']);
};
$pm->childFirst();
$pm->run();
$pm->expectExitCode(0);
echo "DONE\n";
?>
--EXPECTF--
buffer full
[%s]	WARNING	Socket::handle_sendfile(): sendfile(%s, 0, %d) failed, Error: Invalid argument[22]
close
DONE
