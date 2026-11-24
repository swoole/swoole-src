--TEST--
swoole_websocket_server: a partial HTTP request pipelined after the upgrade must not corrupt the frame buffer
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function (int $pid) use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
        $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        Assert::true($cli->connect('127.0.0.1', $pm->getFreePort(), 1));
        $upgrade = "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" .
            "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        // The unfinished second request leaves a parse offset in the receive buffer.
        $cli->send($upgrade . "GET /next HTTP/1.1\r\nHost: localhost\r\n");
        $response = $cli->recv(2);
        Assert::contains($response, '101 Switching Protocols');
        usleep(100000);
        // The leftover bytes are an invalid frame; the connection is closed, but the server must survive.
        $cli->send("\x81\x85" . random_bytes(9));
        $cli->recv(1);
        $cli->close();

        $ws = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        Assert::true($ws->upgrade('/'));
        $ws->push('hello');
        Assert::same($ws->recv(2)->data, 'hello');
    });
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\WebSocket\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(['log_file' => '/dev/null']);
    $serv->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('Message', function (Swoole\WebSocket\Server $serv, Swoole\WebSocket\Frame $frame) {
        $serv->push($frame->fd, $frame->data);
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
