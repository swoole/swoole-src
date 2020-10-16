--TEST--
swoole_http_server_coro: websocket ping pong
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
        $cli->set(['timeout' => 5]);
        $ret = $cli->upgrade('/websocket');
        Assert::assert($ret);
        $cli->push('Swoole');
        $ret = $cli->recv();
        Assert::same($ret->data, "How are you, Swoole?");
        $ret = $cli->recv();
        Assert::same($ret->opcode, WEBSOCKET_OPCODE_PING);
        $pingFrame = new Frame;
        $pingFrame->opcode = WEBSOCKET_OPCODE_PING;
        // 发送 PING
        $cli->push($pingFrame);
        $ret = $cli->recv();
        Assert::same($ret->opcode, WEBSOCKET_OPCODE_PONG);
    });
    swoole_event_wait();
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
                    if ($frame->opcode === 9) {
                        $pFrame = new Frame;
                        $pFrame->opcode = WEBSOCKET_OPCODE_PONG;
                        $ws->push($pFrame);
                    } else {
                        $ws->push("How are you, {$frame->data}?");
                        $pFrame = new Frame;
                        // 发送 PING
                        $pFrame->opcode = WEBSOCKET_OPCODE_PING;
                        $ws->push($pFrame);
                    }
                }
            }
        });
        $server->start();
        $pm->wakeup();
    });
    swoole_event_wait();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
