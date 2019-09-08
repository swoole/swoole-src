--TEST--
swoole_http_server: cookie with samesite
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $cli = new Swoole\Coroutine\Http\Client('127.0.0.1', $pm->getFreePort());
        $cli->get('/');
        Assert::assert($cli->set_cookie_headers ===
            [
                'a=123; samesite=Lax',
            ]
        );
    });
    swoole_event_wait();
    echo "SUCCESS\n";
    $pm->kill();
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('0.0.0.0', $pm->getFreePort(), SWOOLE_BASE);
    $http->set(['worker_num' => 1, 'log_file' => '/dev/null']);
    $http->on('request', function (swoole_http_request $request, swoole_http_response $response) {
        $response->cookie('a', '123', 0, '', '', false, false, 'Lax');
        $response->end();
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
SUCCESS
