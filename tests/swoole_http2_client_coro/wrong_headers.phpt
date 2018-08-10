--TEST--
swoole_http2_client_coro: http2 with wrong headers
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require_once __DIR__ . '/../include/bootstrap.php';
go(function () {
    $domain = 'www.swoole.com';
    $cli = new Swoole\Coroutine\Http2\Client($domain, 443, true);
    $cli->set([
        'timeout' => 10,
        'ssl_host_name' => $domain
    ]);
    $cli->connect();

    $req = new swoole_http2_request;
    $req->path = '/';
    $req->headers = 1;
    assert($cli->send($req));
    assert(is_array($req->headers)); // check array
    /**@var $response swoole_http2_response */
    $response = $cli->recv();
    echo $response->statusCode;
    assert(stripos($response->data, 'swoole') !== false);
});
?>
--EXPECT--
200