--TEST--
swoole_http2_client_coro: http2 without gzip and recv big data (window-update)
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_travis('travis network');
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
    $req->path = '/signup?next=/';
    $req->headers = [
        'Host' => $domain,
        "User-Agent" => 'Chrome/49.0.2587.3',
        'Accept' => 'text/html,application/xhtml+xml,application/xml',
        'Accept-encoding' => ''
    ];
    $i = 5;
    while ($i--) {
        Assert::assert($cli->send($req));
    }
    $i = 5;
    $map = [];
    while ($i--) {
        /**@var $response swoole_http2_response */
        $response = $cli->recv();
        Assert::same($response->statusCode, 200);
        Assert::assert(strpos($response->data, 'zhihu') !== false);
        $map[] = $response->streamId;
    }
    Assert::assert(!array_diff($map, [1, 3, 5, 7, 9]));
});
?>
--EXPECT--
