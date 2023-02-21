--TEST--
swoole_websocket_server: bug 1
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
/**
 * @link https://wenda.swoole.com/detail/108914
 */
require __DIR__ . '/../include/bootstrap.php';
require __DIR__ . '/../../tests/include/api/swoole_websocket_server/websocket_client.php';

$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    Co\run(function () use ($pm) {
        $cli = new  WebSocketClient('127.0.0.1', $pm->getFreePort(), '/');
        Assert::assert($cli->connect());
        $data1 = get_safe_random(random_int(1024, 8192));
        $cli->send($data1);
        $frame1 = $cli->recv();
        Assert::eq($frame1, md5($data1));

        $data2 = get_safe_random(random_int(65536, 65536 * 2));
        $pkt2 = Swoole\WebSocket\Server::pack($data2, WEBSOCKET_OPCODE_TEXT);

        $socket = $cli->getSocket();

        $socket->send(substr($pkt2, 0, 4));
        usleep(1000);
        $socket->send(substr($pkt2, 4));

        $frame2 = $cli->recv();
        Assert::eq($frame2, md5($data2));
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\WebSocket\Server('127.0.0.1', $pm->getFreePort());
    $serv->set([
        'open_http2_protocol' => true,
        'log_file' => '/dev/null',
    ]);
    $serv->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('message', function (Swoole\WebSocket\Server $server, Swoole\WebSocket\Frame $frame) {
        $server->push($frame->fd, md5($frame->data));
    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
