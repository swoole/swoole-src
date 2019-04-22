--TEST--
swoole_http_server: unset header of response
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $cli = new \Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        assert($cli->get('/'));
        echo "{$cli->statusCode}\n";
        Assert::true(!isset($cli->headers['foo']));
        Assert::eq($cli->headers['bar'], 'Foo');
        echo "{$cli->body}\n";
        $pm->kill();
    });
};

$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(['log_file' => '/dev/null']);
    $http->on("workerStart", function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on("request", function (swoole_http_request $request, swoole_http_response $response) {
        $response->header('Foo', 'Bar');
        $response->status(500);
        unset($response->header);
        $response->header('Bar', 'Foo');
        $response->end("just an 500 error for fun\n");
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
500
just an 500 error for fun
