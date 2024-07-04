--TEST--
swoole_http2_client_coro: connect twice
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Channel;
use Swoole\Http2\Request;
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

run(function () {
    $client = new \Swoole\Coroutine\Http2\Client('httpbin.org', 443, true);
    $chan = new Channel(1);
    go(function () use ($client, $chan) {
        $client->connect();
        $req = new Request();
        $uuid = uniqid();
        $req->method = 'GET';
        $req->path = '/base64/' . base64_encode($uuid);
        $client->send($req);
        $chan->push(true);
        $resp = $client->recv();
        Assert::eq($resp->statusCode, 200);
        Assert::eq($resp->data, $uuid);
        $chan->pop();
    });
    go(function () use ($client, $chan) {
        Assert::eq($client->connect(), false);
        $uuid = uniqid();
        $req = new Request();
        $req->method = 'GET';
        $req->path = '/base64/' . base64_encode($uuid);
        $client->send($req);
        $chan->push(true);
        Assert::eq($client->recv(), false);
        $chan->pop();
    });
});

?>
--EXPECT--
