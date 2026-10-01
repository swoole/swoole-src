--TEST--
swoole_http2_server: reject response header blocks larger than the peer frame limit
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

$pm->parentFunc = function () use ($pm) {
    Swoole\Coroutine\run(function () use ($pm) {
        foreach (['/header', '/trailer'] as $path) {
            $client = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
            Assert::true($client->connect());

            $request = new Swoole\Http2\Request;
            $request->path = $path;
            Assert::greaterThan($client->send($request), 0);
            if ($path === '/trailer') {
                Assert::notSame($client->recv(), false);
            }
            Assert::false($client->recv());

            $retry = new Swoole\Http2\Request;
            Assert::false($client->send($retry));
        }
    });

    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'open_http2_protocol' => true,
        'log_file' => '/dev/null',
    ]);
    $server->on('WorkerStart', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('Request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        if ($request->server['request_uri'] === '/header') {
            $response->header('x-large', str_repeat('0', 100000));
            Assert::false($response->end('body'));
        } else {
            Assert::true($response->write('body'));
            $response->trailer('x-large', str_repeat('0', 100000));
            Assert::false($response->end());
        }
    });
    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
