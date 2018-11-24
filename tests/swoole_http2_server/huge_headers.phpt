--TEST--
swoole_http2_server: huge headers
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
        $cli->set(['timeout' => 5]);
        $cli->connect();

        $request = new swoole_http2_request;
        $request->path = '/';
        $request->headers = [
            'host' => $domain,
            "user-agent" => 'Chrome/49.0.2587.3',
            'accept' => 'text/html,application/xhtml+xml,application/xml',
        ];
        for ($i = 1024; $i--;) {
            $request->headers[md5(mt_rand(1, 65535))] = sha1(openssl_random_pseudo_bytes(32));
        }
        assert($cli->send($request));
        $response = $cli->recv();
        assert($response->statusCode === 200);
        assert(json_encode($request->headers) === $response->data);
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
    $http->on("WorkerStart", function () use ($pm) { $pm->wakeup(); });
    $http->on("request", function (swoole_http_request $request, swoole_http_response $response) {
        // foreach ($request->header as $name => $value) {
        //     $response->header($name, $value);
        // }
        $response->end(json_encode($request->header));
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
