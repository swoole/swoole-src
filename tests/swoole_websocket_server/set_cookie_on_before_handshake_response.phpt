--TEST--
swoole_websocket_server: websocket server set cookie on beforeHandshakeResponse (#3270)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->initFreePorts();
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $cli = new Co\Http\Client('127.0.0.1', $pm->getFreePort());
        if (Assert::true($cli->upgrade('/'))) {
            Assert::same($cli->set_cookie_headers, [
                'abc=def'
            ]);
        }
    });
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\WebSocket\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('beforeHandShakeResponse', function (\Swoole\Http\Request $request, \Swoole\Http\Response $response) {
        $response->cookie('abc', 'def');
    });
    $server->on('message', function () { });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
