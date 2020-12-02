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
        Assert::assert($cli->get('/'));
        echo "{$cli->statusCode}\n";
        Assert::true(!isset($cli->headers['foo']));
        Assert::same($cli->headers['bar'], 'Foo');
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
        try {
            unset($response->header);
        } catch (Error $e) {
            echo $e->getMessage() . PHP_EOL;
            $response->header('Foo', null);
        }
        $response->header('Bar', 'Foo');
        $response->end("just an 500 error for fun\n");
    });
    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Property header of class Swoole\Http\Response cannot be unset
500
just an 500 error for fun
