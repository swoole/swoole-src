--TEST--
swoole_http_client_coro/websocket: bug use client in server
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->set(['timeout' => -1]);
        $ret = $cli->upgrade('/');
        Assert::assert($ret);
        echo $cli->recv()->data;
        for ($i = 0; $i < 5; $i++) {
            $cli->push("hello server\n", SWOOLE_WEBSOCKET_OPCODE_TEXT, true);
            echo ($cli->recv(1))->data;
            co::sleep(0.1);
        }
        $cli->close();
    });
    swoole_event::wait();
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $ws = new swoole_websocket_server('127.0.0.1', $pm->getFreePort());
    $ws->set([
        'log_file' => '/dev/null',
        'worker_num' => 1
    ]);
    $ws->on('workerStart', function (swoole_websocket_server $serv) use ($pm) {
        $pm->wakeup();
    });
    $ws->on('open', function (swoole_websocket_server $ws, swoole_http_request $request) {
        $ws->push($request->fd, "server: hello, welcome\n");
    });
    $ws->on('message', function (swoole_websocket_server $ws, swoole_websocket_frame $frame) {
        echo "client: {$frame->data}";
        $frame->data = str_replace('server', 'client', $frame->data);
        $ws->push($frame->fd, "server-reply: {$frame->data}");
    });
    $ws->on('close', function (swoole_websocket_server $ws, int $fd) {
        echo "client-{$fd} is closed\n";
    });
    $ws->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
server: hello, welcome
client: hello server
server-reply: hello client
client: hello server
server-reply: hello client
client: hello server
server-reply: hello client
client: hello server
server-reply: hello client
client: hello server
server-reply: hello client
client-1 is closed
