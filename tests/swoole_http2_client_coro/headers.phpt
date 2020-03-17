--TEST--
swoole_http2_client_coro: http2 headers auto to lower
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $domain = 'mail.qq.com';
    $cli = new Swoole\Coroutine\Http2\Client($domain, 443, true);
    $cli->set([
        'timeout' => 10,
        'ssl_host_name' => $domain
    ]);
    $cli->connect();

    $req = new Swoole\Http2\Request;
    $req->path = '/';
    // auto to-lower
    $req->headers = [
        'Host' => $domain,
        'User-Agent' => 'Chrome/49.0.2587.3',
        'Accept' => 'text/html,application/xhtml+xml,application/xml',
        'Accept-encoding' => 'gzip',
    ];
    for ($n = 5; $n--;) {
        Assert::assert($cli->send($req));
        $response = $cli->recv();
        echo "{$response->statusCode}\n";
    }
});
?>
--EXPECT--
200
200
200
200
200
