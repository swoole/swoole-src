--TEST--
swoole_http_server_coro: websocket ping
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\WebSocket\Frame;
use Swoole\Coroutine\Http\Server;
use Swoole\Coroutine\Http\Client;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $cli = new Client('127.0.0.1', $pm->getFreePort());
        $cli->set([
            'timeout' => 5,
            'open_websocket_ping_frame' => true,
            'open_websocket_pong_frame' => true,
            'open_websocket_close_frame' => true,
        ]);
        $ret = $cli->upgrade('/websocket');
        Assert::assert($ret);
        $cli->push('Swoole');
        $ret = $cli->recv();
        Assert::same($ret->opcode, WEBSOCKET_OPCODE_PING);
    });
    Swoole\Event::wait();
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    go(function () use ($pm) {
        $server = new Server("127.0.0.1", $pm->getFreePort(), false);
        $server->handle('/websocket', function ($request, $ws) {
            $ws->upgrade();
            while (true) {
                $frame = $ws->recv();
                if ($frame === false) {
                    echo "error : " . swoole_last_error() . "\n";
                    break;
                } else if ($frame === '') {
                    break;
                } else {
                    usleep(10000);
                    $ws->ping();
                }
            }
        });
        $server->start();
        $pm->wakeup();
    });
    Swoole\Event::wait();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
