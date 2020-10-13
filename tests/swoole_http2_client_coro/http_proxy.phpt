--TEST--
swoole_http2_client_coro: get with http_proxy
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_no_http_proxy();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Http2\Client;
use Swoole\Http2\Request;

Co\run(function () {
    $domain = 'cloudflare.com';
    $c = new Client($domain, 443, true);
    $c->set([
        'timeout' => 10,
        'ssl_host_name' => $domain,
        'http_proxy_host' => HTTP_PROXY_HOST,
        'http_proxy_port' => HTTP_PROXY_PORT,
    ]);
    Assert::true($c->connect(), var_dump_return($c));
    $r = new Request();
    $r->method = 'GET';
    $r->path = '/';
    $r->headers = [
        'host' => $domain,
    ];
    $c->send($r);
    $response = $c->recv();
    Assert::notEmpty($response);
    Assert::eq($response->statusCode, 301);
    Assert::eq($response->headers['location'], 'https://www.cloudflare.com/');
});
?>
--EXPECT--
