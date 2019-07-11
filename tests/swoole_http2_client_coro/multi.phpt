--TEST--
swoole_http2_client_coro: http2 error and dead wait
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
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
    Assert::true($cli->connect());
    Assert::true($cli->connected);

    $req = new Swoole\Http2\Request;
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
        Assert::assert($cli->send($req));
    }
    $stream_map = [];
    $responses_headers_count_map = [];
    $i = 0;
    while ($cli->connected) {
        $response = $cli->recv(0.1); // it's for the test, you should make timeout bigger
        if ($response) {
            echo "$response->statusCode\n";
            $responses_headers_count_map[] = count($response->headers);
            Assert::contains($response->data, 'Cookie');
            $stream_map[] = $response->streamId;
            if (++$i === 4) {
                break;
            }
        }
    }
    Assert::assert(empty(array_diff([1, 3, 5, 7], $stream_map)));
    Assert::same(count(array_unique($responses_headers_count_map)), 1);
    Assert::assert($responses_headers_count_map[0] > 10);
});
swoole_event::wait();
?>
--EXPECT--
200
200
200
200
