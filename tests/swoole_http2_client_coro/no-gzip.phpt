--TEST--
swoole_http2_client_coro: http2 without gzip and recv big data (window-update)
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_in_docker('travis network');
?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
go(function () {
    $domain = 'www.zhihu.com';
    $cli = new Swoole\Coroutine\Http2\Client($domain, 443, true);
    $cli->set([
        'timeout' => -1,
        'ssl_host_name' => $domain
    ]);
    $cli->connect();

    $req = new swoole_http2_request;
    $req->path = '/signup?next=/';
    $req->headers = [
        'Host' => $domain,
        "User-Agent" => 'Chrome/49.0.2587.3',
        'Accept' => 'text/html,application/xhtml+xml,application/xml',
        'Accept-encoding' => ''
    ];
    $i = 5;
    while ($i--) {
        assert($cli->send($req));
    }
    $i = 5;
    $map = [];
    while ($i--) {
        /**@var $response swoole_http2_response */
        $response = $cli->recv();
        assert($response->statusCode === 200);
        assert(strpos($response->data, 'zhihu') !== false);
        $map[] = $response->streamId;
    }
    assert(!array_diff($map, [1, 3, 5, 7, 9]));
});
?>
--EXPECT--