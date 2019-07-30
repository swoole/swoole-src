--TEST--
swoole_http2_client_coro: cookies
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http2\Client('127.0.0.1', $pm->getFreePort());
        $cli->connect();
        $request = new Swoole\Http2\Request;
        for ($n = MAX_REQUESTS; $n--;) {
            $request->cookies = [];
            for ($k = 32; $k--;) {
                $request->cookies[get_safe_random()] = get_safe_random();
            }
            Assert::assert($cli->send($request));
            $response = $cli->recv(1);
            Assert::same('OK', $response->data);
            Assert::same($request->cookies, $response->cookies);
        }
        echo "DONE\n";
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $http = new Swoole\Http\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null',
        'open_http2_protocol' => true
    ]);
    $http->on('workerStart', function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) {
        foreach ($request->cookie as $name => $value) {
            $response->cookie($name, $value);
        }
        $response->end('OK');
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
