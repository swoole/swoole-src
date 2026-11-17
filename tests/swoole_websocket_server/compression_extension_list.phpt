--TEST--
swoole_websocket_server: negotiate compression from extension lists without matching quoted parameters
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_not_defined('SWOOLE_HAVE_ZLIB');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

foreach ([SWOOLE_BASE, SWOOLE_PROCESS] as $mode) {
    $pm = new ProcessManager;
    $pm->parentFunc = static function () use ($pm) {
        Swoole\Coroutine\run(static function () use ($pm) {
            $offers = [
                ['permessage-deflate', true],
                ['x-example, permessage-deflate; client_max_window_bits', true],
                ["x-example; p=\"a,b\", \tpermessage-deflate \t; client_max_window_bits", true],
                ['permessage-deflate , x-example', true],
                ['x-example; p="a,b"; q="c;d", permessage-deflate', true],
                ['x-example; p=", permessage-deflate"', false],
                ['x-example; p="escaped' . '\\' . '", permessage-deflate"', false],
                ['x-permessage-deflate', false],
                ['permessage-deflate-extra', false],
                ['x-example', false],
            ];
            foreach ($offers as [$offer, $accepted]) {
                $client = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
                $client->set(['timeout' => 2, 'websocket_compression' => false]);
                $client->setHeaders(['Sec-WebSocket-Extensions' => $offer]);
                Assert::true($client->upgrade('/'));
                Assert::same(isset($client->headers['sec-websocket-extensions']), $accepted, $offer);
                if ($accepted) {
                    Assert::contains($client->headers['sec-websocket-extensions'], 'permessage-deflate');
                }
                $client->close();
            }
        });
        $pm->kill();
    };
    $pm->childFunc = static function () use ($pm, $mode) {
        $server = new Swoole\WebSocket\Server('127.0.0.1', $pm->getFreePort(), $mode);
        $server->set(['worker_num' => 1, 'log_file' => '/dev/null', 'websocket_compression' => true]);
        $server->on('WorkerStart', static function () use ($pm) { $pm->wakeup(); });
        $server->on('Message', static function () {});
        $server->start();
    };
    $pm->childFirst();
    $pm->run();
}
echo "DONE\n";
?>
--EXPECT--
DONE
