--TEST--
swoole_http2_client_coro: http2 error and dead wait
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
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
    $req->path = '/terms/privacy';
    $req->headers = [
        'Host' => $domain,
        "User-Agent" => 'Chrome/49.0.2587.3',
        'Accept' => 'text/html,application/xhtml+xml,application/xml',
        'Accept-encoding' => 'gzip',
    ];
    /**@var $response swoole_http2_response */
    $i = 4;
    while ($i--) {
        assert($cli->send($req));
    }
    $stream_map = [];
    $responses_headers_count_map = [];
    $i = 0;
    while (true) {
        $response = $cli->recv(0.1); // it's for the test, you should make timeout bigger
        if ($response) {
            echo "$response->statusCode\n";
            $responses_headers_count_map[] = count($response->headers);
            assert(strpos($response->data, 'Cookie') !== false);
            $stream_map[] = $response->streamId;
            if (++$i === 4) {
                break;
            }
        }
    }
    assert(empty(array_diff([1, 3, 5, 7], $stream_map)));
    $responses_headers_count_map = array_unique($responses_headers_count_map);
    assert(count($responses_headers_count_map) === 1);
    assert($responses_headers_count_map > 10);
});
?>
--EXPECT--
200
200
200
200