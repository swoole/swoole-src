--TEST--
swoole_http2_client_coro: http2 without gzip and recv big data (window-update)
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $domain = 'www.zhihu.com';
    $cli = new Swoole\Coroutine\Http2\Client($domain, 443, true);
    $cli->set([
        'timeout' => -1,
        'ssl_host_name' => $domain
    ]);
    $cli->connect();

    $req = new Swoole\Http2\Request;
    $req->method = 'POST';
    $req->path = '/api/v4/answers/300000000/voters';
    $req->headers = [
        'host' => $domain,
        "user-agent" => 'Chrome/49.0.2587.3',
        'accept' => 'text/html,application/xhtml+xml,application/xml',
        'accept-encoding' => 'gzip'
    ];
    $req->data = '{"type":"up"}';
    $cli->send($req);
    $response = $cli->recv();
    Assert::true(in_array(json_decode($response->data)->error->code, [602, 10002], true));
});
?>
--EXPECT--
