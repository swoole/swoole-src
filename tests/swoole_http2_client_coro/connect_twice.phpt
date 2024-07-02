--TEST--
swoole_http2_client_coro: connect twice
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Http2\Request;
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

run(function () {
    $client = new \Swoole\Coroutine\Http2\Client('www.zhihu.com', 443, true);
    $chan   = new \Swoole\Coroutine\Channel(1);
    go(function () use ($client, $chan) {
        $client->connect();
        $req = new Request();
        $req->method = 'GET';
        $req->path   = '/io?io=' . str_repeat('xxx', 1000);
        $client->send($req);
        $chan->push(true);
        $resp = $client->recv();
        Assert::eq($resp->statusCode, 302);
        Assert::contains($resp->data, '302 Found');
        $chan->pop();
    });
    go(function () use ($client, $chan) {
        Assert::eq($client->connect(), false);
        $req = new Request();
        $req->method = 'GET';
        $req->path   = '/io?io=xxx';
        $client->send($req);
        $chan->push(true);
        Assert::eq($client->recv(), false);
        $chan->pop();
    });
});

?>
--EXPECT--
