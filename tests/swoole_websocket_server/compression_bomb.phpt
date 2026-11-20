--TEST--
swoole_websocket_server: compressed message exceeding package_max_length after inflate is dropped
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_win();
skip_if_not_defined('SWOOLE_HAVE_ZLIB');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http\Client;
use Swoole\WebSocket\Frame;
use Swoole\WebSocket\Server;
use SwooleTest\ProcessManager;

$pm = new ProcessManager();
$pm->parentFunc = function (int $pid) use ($pm) {
    Co\run(function () use ($pm) {
        $cli = new Client('127.0.0.1', $pm->getFreePort());
        $cli->set(['timeout' => 5, 'websocket_compression' => true]);
        Assert::true($cli->upgrade('/'));
        $flags = SWOOLE_WEBSOCKET_FLAG_FIN | SWOOLE_WEBSOCKET_FLAG_COMPRESS;
        // compresses to a few KB, but inflates far beyond package_max_length
        $cli->push(str_repeat("\0", 8 * 1024 * 1024), SWOOLE_WEBSOCKET_OPCODE_BINARY, $flags);
        $cli->push(str_repeat('a', 1000), SWOOLE_WEBSOCKET_OPCODE_TEXT, $flags);
        $frame = $cli->recv();
        Assert::same($frame->data, '1000');
        echo "DONE\n";
    });
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $server->set([
        'log_file' => '/dev/null',
        'websocket_compression' => true,
        'package_max_length' => 64 * 1024,
    ]);
    $server->on('workerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('message', function (Server $server, Frame $frame) {
        $server->push($frame->fd, (string) strlen($frame->data));
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
