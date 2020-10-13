--TEST--
swoole_http_client_coro: lowercase header
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {

        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort(), false);
        $cli->set(['timeout' => 10,
            'lowercase_header' => false,
        ]);
        Assert::assert($cli->get('/'));
        Assert::assert(array_key_exists('Hello-world', $cli->getHeaders()));
        Assert::assert(!array_key_exists('hello-world', $cli->getHeaders()));


        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort(), false);
        Assert::assert($cli->get('/'));
        Assert::assert(!array_key_exists('Hello-world', $cli->getHeaders()));
        Assert::assert(array_key_exists('hello-world', $cli->getHeaders()));

        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $http->set([
        'log_file' => '/dev/null'
    ]);
    $http->on('WorkerStart', function (\swoole_server $serv) {
        /**
         * @var $pm ProcessManager
         */
        global $pm;
        $pm->wakeup();
    });
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        $response->header('Hello-world', 'swoole', false);
        $response->end();
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
