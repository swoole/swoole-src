--TEST--
swoole_http_server_coro: websocket compression
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Http\Client;
use Swoole\Coroutine\Http\Server;
use Swoole\Http\Request;
use Swoole\Http\Response;
use function Swoole\Coroutine\run;

run(function () {
    $server = new Server('127.0.0.1');
    $server->set([
        'websocket_compression' => true,
    ]);
    $server->handle('/', function (Request $request, Response $ws) {
        if (($request->header['upgrade'] ?? '') === 'websocket') {
            if ($ws->upgrade()) {
                while ($frame = $ws->recv()) {
                    $ws->push($frame);
                }
            }
        } else {
            $ws->status(400);
            $ws->end();
        }
    });

    Coroutine::create(function () use ($server) {
        $cli = new Client('127.0.0.1', $server->port);
        $cli->set([
            'timeout' => 5,
            'websocket_compression' => true
        ]);
        $ret = $cli->upgrade('/');
        if (!Assert::assert($ret)) {
            return;
        }
        for ($n = MAX_REQUESTS; $n--;) {
            $data = get_safe_random();
            $cli->push(
                $data,
                SWOOLE_WEBSOCKET_OPCODE_TEXT,
                SWOOLE_WEBSOCKET_FLAG_FIN | SWOOLE_WEBSOCKET_FLAG_COMPRESS
            );
            $frame = $cli->recv();
            if (!Assert::same($frame->data, $data)) {
                return;
            }
            if (!Assert::eq($frame->flags & SWOOLE_WEBSOCKET_FLAG_COMPRESS, defined('SWOOLE_HAVE_ZLIB'))) {
                return;
            }
        }
        $server->shutdown();
        echo "DONE\n";
    });

    $server->start();
});

?>
--EXPECT--
DONE
