--TEST--
swoole_websocket_server: exists & isEstablished
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$connections = [];
$pm = new ProcessManager;
$pm->parentFunc = function (int $pid) use ($pm) {
    $ready = new Chan;
    for ($c = 0; $c < MAX_CONCURRENCY; $c++) {
        go(function () use ($pm, $ready, $c) {
            /* @var $connections Co\Http\Client[][] */
            global $connections;
            $connections[$c] = [
                'cli' => new Co\Http\Client('127.0.0.1', $pm->getFreePort()),
                'type' => array_random(['null', 'http', 'websocket']),
                'fd' => -1
            ];
            if ($connections[$c]['type'] !== 'null') {
                if (!Assert::assert($connections[$c]['cli']->get('/'))) {
                    exit;
                }
                $connections[$c]['fd'] = (int)$connections[$c]['cli']->body;
                if ($connections[$c]['type'] === 'websocket') {
                    if (!Assert::assert($connections[$c]['cli']->upgrade('/'))) {
                        exit;
                    }
                }
            }
            $ready->push(true);
        });
    }
    go(function () use ($pm, $ready) {
        global $connections;
        for ($c = 0; $c < MAX_CONCURRENCY; $c++) {
            Assert::true($ready->pop());
        }
        $cli = new Co\Http\Client('127.0.0.1', $pm->getFreePort());
        if (Assert::assert($cli->upgrade('/'))) {
            for ($c = 0; $c < MAX_CONCURRENCY; $c++) {
                if (!Assert::assert($cli->push($connections[$c]['fd']))) {
                    exit;
                }
                $frame = $cli->recv();
                if (!Assert::assert($frame instanceof Swoole\WebSocket\Frame)) {
                    exit;
                }
                // var_dump($connections[$c], $frame->data);
                if (!Assert::assert($frame->data === ($connections[$c]['type'] ?? 'null'))) {
                    exit;
                }
            }
        }
        $connections = null;
        echo "DONE\n";
    });
    Swoole\Event::wait();
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\WebSocket\Server ('127.0.0.1', $pm->getFreePort(), SERVER_MODE_RANDOM);
    $server->set(['log_file' => '/dev/null']);
    $server->on('start', function () use ($pm) {
        switch_process();
        $pm->wakeup();
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        $response->end($request->fd);
    });
    $server->on('message', function (Swoole\WebSocket\Server $server, Swoole\WebSocket\Frame $frame) {
        $fd = (int)$frame->data;
        $server->push(
            $frame->fd,
            $server->isEstablished($fd) ? 'websocket' : ($server->exists($fd) ? 'http' : 'null')
        );
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
