--TEST--
swoole_http2_server: big data
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $domain = '127.0.0.1';
        $cli = new Swoole\Coroutine\Http2\Client($domain, $pm->getFreePort(), true);
        $cli->set(['timeout' => 10]);
        assert($cli->connect());

        $req = new swoole_http2_request;
        $req->method = 'POST';
        $req->path = '/';
        $req->headers = [
            'Host' => $domain,
            "User-Agent" => 'Chrome/49.0.2587.3',
            'Accept' => 'text/html,application/xhtml+xml,application/xml',
            'Accept-encoding' => 'gzip'
        ];
        $req->data = openssl_random_pseudo_bytes(65535 + mt_rand(0, 65535));
        assert($cli->send($req));
        $res = $cli->recv();
        assert($res->statusCode === 200);
        assert(md5($req->data) === md5($res->data));
        $pm->kill();
    });
    swoole_event::wait();
};
$pm->childFunc = function () use ($pm) {
    $http = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $http->set([
        'worker_num' => 1,
        'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key'
    ]);
    $http->on("WorkerStart", function ($serv, $wid) use ($pm) {
        $pm->wakeup();
    });
    $http->on("request", function (swoole_http_request $request, swoole_http_response $response) {
        $response->end($request->rawcontent());
    });
    $http->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
