--TEST--
swoole_websocket_server: malformed data
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
const LOG_FILE = __DIR__ . '/swoole.log';
$count = 0;
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm, &$count) {
    $bytes = [chr(25)];
    swoole_loop_n(255, function () use (&$bytes) {
        $bytes[] = chr(255);
    });

    Co\run(function () use ($bytes, $pm) {
        $cli = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP);
        $connected = $cli->connect('127.0.0.1', $pm->getFreePort());
        Assert::assert($connected);
        $cli->send("GET /chat HTTP/1.1\r\n" .
            "Host: localhost\r\n" .
            "Upgrade: websocket\r\n" .
            "Connection: Upgrade\r\n" .
            "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n" .
            "Sec-WebSocket-Protocol: chat\r\n" .
            "Sec-WebSocket-Version: 13\r\n\r\n");
        $r1 = $cli->recv();
        Assert::contains($r1, 'HTTP/1.1 101 Switching Protocols');
        $cli->send(implode('', $bytes));
        $r2 = $cli->recv();
        Assert::eq($r2, false);
        Assert::eq($cli->errCode, SOCKET_ECONNRESET);
    });
    $pm->kill();
    $log = file_get_contents(LOG_FILE);
    Assert::contains($log, 'malformed data');
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $serv = new Swoole\WebSocket\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $serv->set([
        'log_file' => LOG_FILE,
    ]);
    $serv->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $serv->on('message', function (Swoole\WebSocket\Server $server, Swoole\WebSocket\Frame $frame) {

    });
    $serv->start();
};
$pm->childFirst();
$pm->run();
unlink(LOG_FILE);
?>
--EXPECT--
DONE
