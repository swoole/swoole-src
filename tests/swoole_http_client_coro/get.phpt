--TEST--
swoole_http_client_coro: http client
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
        echo httpGetBody("http://127.0.0.1:{$pm->getFreePort()}/");
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
        $cli = new Swoole\Coroutine\Http\Client('www.qq.com', 443, true);
        $cli->set(['timeout' => 10]);
        $cli->setHeaders([
            'Host' => 'www.qq.com',
            'User-Agent' => 'Chrome/49.0.2587.3',
            'Accept' => 'text/html,application/xhtml+xml,application/xml',
            'Accept-Encoding' => 'gzip',
        ]);
        $ret = ($cli->get('/'));
        if (!$ret) {
            $response->end("ERROR\n");
            return;
        } else {
            $response->end("OK\n");
            $cli->close();
        }
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
OK
