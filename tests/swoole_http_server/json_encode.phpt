--TEST--
swoole_http_server: json_encode or serialize Swoole\Http\Request::class OR Swoole\Http\Response::class
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/test") . PHP_EOL;
        $pm->kill();
    });
};

$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Http\Server('0.0.0.0', $pm->getFreePort(), SWOOLE_BASE);
    $server->set(['log_file' => '/dev/null']);
    $server->on('start', function () use ($pm) {
        $pm->wakeup();
    });
    $server->on('request', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($pm) {
        Assert::true($request->fd > 0);
        Assert::true($response->fd > 0);

        $result = json_decode(json_encode($request), true);
        Assert::true($result['fd'] > 0);

        $result = json_decode(json_encode($response), true);
        Assert::true($result['fd'] > 0);

        $response->end('OK');
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
