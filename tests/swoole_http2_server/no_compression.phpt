--TEST--
swoole_http2_server: no compression with http2
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $domain = '127.0.0.1';
        $cli = new Swoole\Coroutine\Http2\Client($domain, $pm->getFreePort(), true);
        $cli->set([
            'timeout' => -1,
        ]);
        $cli->connect();

        $req = new Swoole\Http2\Request;
        $req->path = '/';
        $req->headers = [
            'Host' => $domain,
            "User-Agent" => 'Chrome/49.0.2587.3',
            'Accept' => 'text/html,application/xhtml+xml,application/xml',
        ];
        for ($n = MAX_REQUESTS; $n--;) {
            Assert::assert($cli->send($req));
            $response = $cli->recv();
            Assert::eq($response->statusCode, 200);
            Assert::eq(md5_file(__DIR__ . '/../../README.md'), md5($response->data));
        }
        $pm->kill();
    });
    swoole_event::wait();
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $http->set([
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'http_compression' => false,
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    ]);
    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });
    $http->on("request", function (swoole_http_request $request, swoole_http_response $response) {
        $response->end(co::readFile(__DIR__ . '/../../README.md'));
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
