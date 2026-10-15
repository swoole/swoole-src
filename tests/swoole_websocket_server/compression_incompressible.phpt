--TEST--
swoole_websocket_server: incompressible messages preserve control frames across reconnects
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_defined('SWOOLE_HAVE_ZLIB');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\WebSocket\Frame;
use Swoole\WebSocket\Server;

$payloads = require __DIR__ . '/../include/websocket_compression_fixture.inc';
foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $pm             = new ProcessManager();
    $pm->parentFunc = function () use ($pm, $payloads) {
        Coroutine\run(function () use ($pm, $payloads) {
            for ($connection = 0; $connection < 2; $connection++) {
                $client = new Client('127.0.0.1', $pm->getFreePort());
                $client->set([
                    'timeout'                    => 5,
                    'websocket_compression'      => true,
                    'open_websocket_ping_frame'  => true,
                    'open_websocket_pong_frame'  => true,
                    'open_websocket_close_frame' => true,
                ]);
                Assert::true($client->upgrade('/'));
                Assert::contains($client->headers['sec-websocket-extensions'], 'permessage-deflate');

                foreach ($payloads as $index => $data) {
                    Assert::true($client->push('request:' . $index));
                    $frame = $client->recv();
                    Assert::isInstanceOf($frame, Frame::class);
                    Assert::same($frame->opcode, WEBSOCKET_OPCODE_BINARY);
                    Assert::true($frame->finish);
                    Assert::same($frame->data, $data);

                    foreach ([WEBSOCKET_OPCODE_PING, WEBSOCKET_OPCODE_PONG] as $opcode) {
                        $frame = $client->recv();
                        Assert::isInstanceOf($frame, Frame::class);
                        Assert::same($frame->opcode, $opcode);
                        Assert::same($frame->data, 'control');
                        Assert::true($frame->finish);
                        Assert::same($frame->flags & SWOOLE_WEBSOCKET_FLAG_RSV1, 0);
                    }

                    Assert::true($client->push('heartbeat', WEBSOCKET_OPCODE_PING));
                    $frame = $client->recv();
                    Assert::isInstanceOf($frame, Frame::class);
                    Assert::same($frame->opcode, WEBSOCKET_OPCODE_PONG);
                    Assert::same($frame->data, 'heartbeat');
                    Assert::true($frame->finish);
                    Assert::same($frame->flags & SWOOLE_WEBSOCKET_FLAG_RSV1, 0);
                }

                Assert::true($client->push('close'));
                $frame = $client->recv();
                Assert::isInstanceOf($frame, Swoole\WebSocket\CloseFrame::class);
                Assert::true($frame->finish);
                Assert::same($frame->code, WEBSOCKET_CLOSE_NORMAL);
                Assert::same($frame->reason, 'done');
                $client->close();
            }
        });
        $pm->kill();
    };
    $pm->childFunc = function () use ($pm, $mode, $payloads) {
        $server = new Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set([
            'worker_num'            => 1,
            'websocket_compression' => true,
            'log_file'              => TEST_LOG_FILE,
        ]);
        $server->on('workerStart', function () use ($pm) {
            $pm->wakeup();
        });
        $server->on('message', function (Server $server, Frame $frame) use ($payloads) {
            if ($frame->data === 'close') {
                Assert::true($server->disconnect($frame->fd, WEBSOCKET_CLOSE_NORMAL, 'done'));
                return;
            }
            $index = (int) substr($frame->data, strlen('request:'));
            Assert::true($server->push($frame->fd, $payloads[$index], WEBSOCKET_OPCODE_BINARY));
            Assert::true($server->ping($frame->fd, 'control'));
            Assert::true($server->push($frame->fd, 'control', WEBSOCKET_OPCODE_PONG, 0));
        });
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}

echo "DONE\n";
?>
--EXPECT--
DONE
