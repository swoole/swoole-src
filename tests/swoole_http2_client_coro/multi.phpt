--TEST--
swoole_http2_client_coro: multi
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $domain = 'nghttp2.org';
    $cli = new Swoole\Coroutine\Http2\Client($domain, 443, true);
    $cli->set([
        'timeout' => -1,
        'ssl_host_name' => $domain
    ]);
    Assert::true($cli->connect());
    Assert::true($cli->connected);

    $req = new Swoole\Http2\Request;
    $req->path = '/';
    $req->headers = [
        'Host' => $domain,
        "User-Agent" => 'Chrome/49.0.2587.3',
        'Accept' => 'text/html,application/xhtml+xml,application/xml',
        'Accept-encoding' => 'gzip',
    ];
    /**@var $response swoole\http2\response */
    $i = 4;
    while ($i--) {
        Assert::assert($cli->send($req));
    }
    $stream_map = [];
    $responses_headers_count_map = [];
    $i = 0;
    while ($cli->connected) {
        // it's for the test, you should make timeout bigger
        $response = $cli->recv(0.1);
        if ($response) {
            echo "$response->statusCode\n";
            $responses_headers_count_map[] = count($response->headers);
            Assert::contains($response->data, 'nghttp2.org');
            $stream_map[] = $response->streamId;
            if (++$i === 4) {
                break;
            }
        }
    }
    Assert::assert(empty(array_diff([1, 3, 5, 7], $stream_map)));
    Assert::lessThanEq(count(array_unique($responses_headers_count_map)), 2);
    Assert::assert($responses_headers_count_map[0] > 10);
});
Swoole\Event::wait();
?>
--EXPECT--
200
200
200
200
