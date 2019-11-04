--TEST--
swoole_websocket_server: websocket with large data concurrency
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\WebSocket\Server;
use Swoole\Coroutine\Http\Client;
use Swoole\WebSocket\Frame;
use SwooleTest\ProcessManager as ProcessManager;

$pm = new ProcessManager;
$pm->initRandomData(MAX_REQUESTS);
$pm->parentFunc = function (int $pid) use ($pm) {
    Co\run(function () use ($pm) {
        $cli = new Client('127.0.0.1', $pm->getFreePort());
        $cli->set([
            'timeout' => 5,
            'websocket_compression' => true
        ]);
        $ret = $cli->upgrade('/');
        if (!Assert::assert($ret)) {
            return;
        }
        for ($n = MAX_REQUESTS; $n--;) {
            $data = $pm->getRandomData();
            $cli->push(
                $data,
                SWOOLE_WEBSOCKET_OPCODE_TEXT,
                SWOOLE_WEBSOCKET_FLAG_FIN | SWOOLE_WEBSOCKET_FLAG_RSV1
            );
            $frame = $cli->recv();
            if (!Assert::same($frame->data, $data)) {
                return;
            }
        }
        echo "DONE\n";
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $server->set([
        'log_file' => '/dev/null',
        'websocket_compression' => true
    ]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('message', function (Server $server, Frame $frame) {
        $server->push($frame->fd, $frame);
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
