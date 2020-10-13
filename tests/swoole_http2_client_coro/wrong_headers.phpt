--TEST--
swoole_http2_client_coro: http2 with wrong headers
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
    $req->headers = 1;
    Assert::assert($cli->send($req));
    Assert::assert(is_array($req->headers)); // check array
    /**@var $response swoole_http2_response */
    $response = $cli->recv();
    echo $response->statusCode;
    Assert::assert(stripos($response->data, 'tencent') !== false);
});
?>
--EXPECT--
200
