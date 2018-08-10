--TEST--
swoole_http_server: gzip with http2
--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    go(function () use ($pm) {
        $domain = '127.0.0.1';
        $cli = new Swoole\Coroutine\Http2\Client($domain, 9501, true);
        $cli->set([
            'timeout' => -1,
        ]);
        $cli->connect();

        $req = new swoole_http2_request;
        $req->path = '/';
        $req->headers = [
            'Host' => $domain,
            "User-Agent" => 'Chrome/49.0.2587.3',
            'Accept' => 'text/html,application/xhtml+xml,application/xml',
            'Accept-encoding' => 'gzip'
        ];

        assert($cli->send($req));
        $response = $cli->recv();
        assert($response->statusCode === 200);
        $pm->kill();
    });
    swoole_event::wait();
};

$pm->childFunc = function () use ($pm)
{
    $http = new swoole_http_server("127.0.0.1", 9501, SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);

    $http->set([
        //'log_file' => '/dev/null',
        'open_http2_protocol' => true,
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    ]);

    $http->on("WorkerStart", function ($serv, $wid) {
        global $pm;
        $pm->wakeup();
    });

    $http->on("request", function ($request, swoole_http_response $response) {
        $response->gzip(9);
        $response->end("<h1> hello world</h1><p>".str_repeat('A', 1024)."</p>");
    });

    $http->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
