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
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    Co\run(function () use ($pm) {
        global $count;
        $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->set(['timeout' => 5]);
        Assert::assert($cli->upgrade('/'));
        $data1 = get_safe_random(random_int(1024, 8192));
        $cli->push($data1);
        $frame1 = $cli->recv();
        Assert::eq($frame1->data, md5($data1));

        $data2 = get_safe_random(random_int(65536, 65536 * 2));
        $pkt2 = Swoole\WebSocket\Server::pack($data2, WEBSOCKET_OPCODE_TEXT);

        $cli->socket->sendAll(substr($pkt2, 0, 4));
        usleep(1000);
        $cli->socket->sendAll(substr($pkt2, 4));

        $frame2 = $cli->recv();
        Assert::eq($frame2->data, md5($data2));
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\WebSocket\Server('127.0.0.1', $pm->getFreePort());
    $serv->set([
        'open_http2_protocol' => true,
//        'log_file' => '/dev/null',
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
