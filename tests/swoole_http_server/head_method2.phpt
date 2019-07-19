--TEST--
swoole_http_server: HEAD method 2
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$data = json_encode([
    'code' => 'ok',
    'error' => false,
    'payload' => 'Hello World'
]);

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm, $data) {
    go(function () use ($pm, $data) {
        $headers = httpGetHeaders("http://127.0.0.1:{$pm->getFreePort()}/head/return/none", ['method' => 'HEAD']);
        Assert::eq($headers["content-length"], strlen($data));

        $headers = httpGetHeaders("http://127.0.0.1:{$pm->getFreePort()}/head/return/data", ['method' => 'HEAD']);
        Assert::eq($headers["content-length"], strlen($data));

        $headers = httpGetHeaders("http://127.0.0.1:{$pm->getFreePort()}/post/return/none", ['method' => 'POST']);
        Assert::eq($headers["content-length"], "0");

        $headers = httpGetHeaders("http://127.0.0.1:{$pm->getFreePort()}/post/return/data", ['method' => 'POST']);
        Assert::eq($headers["content-length"], strlen($data));
        
        httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/shutdown") . PHP_EOL;
    });
};

$pm->childFunc = function () use ($pm, $data) {
    go(function () use ($pm, $data) {
        $server = new Co\Http\Server("127.0.0.1", $pm->getFreePort(), false);

        $server->handle('/head/return/none', function ($request, $response) use ($data) {
            $response->header('Content-Type', 'application/json');
            $response->header('Content-Length', strlen($data));
            $response->end();
        });

        $server->handle('/head/return/data', function ($request, $response) use ($data) {
            $response->header('Content-Type', 'application/json');
            $response->header('Content-Length', strlen($data));
            $response->end("swoole");
        });

        $server->handle('/post/return/none', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($data) {
            $response->header('Content-Type', 'application/json');
            $response->end();
        });

        $server->handle('/post/return/data', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($data) {
            $response->header('Content-Type', 'application/json');
            $response->end($data);
        });

        $server->handle('/shutdown', function ($request, $response) use ($server) {
            $response->status(200);
            $server->shutdown();
        });
        $pm->wakeup();
        $server->start();
    });
    Swoole\Event::wait();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Warning: Swoole\Http\Response::end(): HEAD method should not return body in %s/tests/swoole_http_server/head_method2.php on line %d