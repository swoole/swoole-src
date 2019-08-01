--TEST--
swoole_http2_server: conpression with http2
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
            'ssl_cert_file' => SSL_FILE_DIR2 . '/client-cert.pem',
            'ssl_key_file' => SSL_FILE_DIR2 . '/client-key.pem'
        ]);
        $cli->connect();

        $req = new Swoole\Http2\Request;
        $req->path = '/';
        $req->headers = [
            'Host' => $domain,
            "User-Agent" => 'Chrome/49.0.2587.3',
            'Accept' => 'text/html,application/xhtml+xml,application/xml',
            'Accept-encoding' => 'gzip'
        ];
        for ($n = MAX_REQUESTS; $n--;) {
            Assert::assert($cli->send($req));
            $response = $cli->recv();
            Assert::same($response->statusCode, 200);
            Assert::same(md5_file(__DIR__ . '/../../README.md'), md5($response->data));
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
            'http_gzip_level' => 9,
            'http_compression' => true,
            'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
            'ssl_key_file' => SSL_FILE_DIR . '/server.key'
        ] + (IS_IN_TRAVIS ? [] : [
            'ssl_verify_peer' => true,
            'ssl_allow_self_signed' => true,
            'ssl_client_cert_file' => SSL_FILE_DIR2 . '/ca-cert.pem'
        ])
    );
    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });
    $http->on("request", function ($request, swoole_http_response $response) {
        $response->end(co::readFile(__DIR__ . '/../../README.md'));
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
