--TEST--
swoole_http2_client_coro: http2 response cookies
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
go(function () {
    $domain = 'www.bing.com';
    $cli = new Swoole\Coroutine\Http2\Client($domain, 443, true);
    $cli->set([
        'timeout' => 10,
        'ssl_host_name' => $domain
    ]);
    $cli->connect();

    $req = new Swoole\Http2\Request;
    $req->path = '/';
    $req->headers = [
        'Host' => $domain,
        "User-Agent" => 'Chrome/49.0.2587.3',
        'Accept' => 'text/html,application/xhtml+xml,application/xml',
        'Accept-encoding' => 'gzip',
    ];
    Assert::assert($cli->send($req));
    /**@var $response swoole_http2_response */
    $response = $cli->recv();
    Assert::assert(is_array($response->headers));
    Assert::assert(count($response->set_cookie_headers) >= 3);
    // check cookies
    foreach ($response->set_cookie_headers as $set_cookie_header) {
        $cookie = explode(';', $set_cookie_header, 2)[0];
        list($key, $value) = explode('=', $cookie, 2);
        Assert::same($response->cookies[$key], $value);
    }
});
?>
--EXPECT--
