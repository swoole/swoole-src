--TEST--
swoole_websocket_server: closing the connection inside the callback in BASE mode must not corrupt memory
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    Co\run(function () use ($pm) {
        // fragmented message whose final frame makes the server close the connection
        for ($i = 0; $i < 20; $i++) {
            foreach ([WEBSOCKET_OPCODE_TEXT, WEBSOCKET_OPCODE_CLOSE] as $kind) {
                $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
                Assert::assert($cli->upgrade('/'));
                if ($kind === WEBSOCKET_OPCODE_TEXT) {
                    $cli->socket->sendAll(Swoole\WebSocket\Server::pack(str_repeat('a', 100), WEBSOCKET_OPCODE_TEXT, 0));
                    $cli->socket->sendAll(Swoole\WebSocket\Server::pack(str_repeat('b', 100), WEBSOCKET_OPCODE_CONTINUATION, SWOOLE_WEBSOCKET_FLAG_FIN));
                } else {
                    $cli->socket->sendAll(Swoole\WebSocket\Server::pack(pack('n', 1000) . str_repeat('c', 100), WEBSOCKET_OPCODE_CLOSE));
                }
                $cli->socket->recv(8192, 1);
                $cli->close();
            }
        }
        // the server must still be alive
        $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        Assert::assert($cli->upgrade('/'));
        $cli->push('ping');
        Assert::eq($cli->recv(2)->data, 'pong');
    });
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\WebSocket\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set(['worker_num' => 1, 'open_websocket_close_frame' => true, 'log_file' => '/dev/null']);
    $serv->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('message', function (Swoole\WebSocket\Server $server, Swoole\WebSocket\Frame $frame) {
        if ($frame->data === 'ping') {
            $server->push($frame->fd, 'pong');
        } else {
            $server->close($frame->fd);
        }
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
