--TEST--
swoole_http2_client_coro: connect twice
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc';
skip_if_offline();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Http2\Client;
use Swoole\Http2\Request;
use Swoole\Http2\Response;
use function Swoole\Coroutine\run;
use function Swoole\Coroutine\go;

run(function () {
    $domain = 'nghttp2.org';
    $client = new Client($domain, 443, true);
    $client->set([
        'timeout' => 5,
        'ssl_host_name' => $domain,
    ]);
    $chan = new Channel(1);
    go(function () use ($client, $chan, $domain) {
        $connected = $client->connect();
        if (!Assert::true(
            $connected,
            "connect failed: {$client->errCode} {$client->errMsg}"
        )) {
            return;
        }
        $req = new Request();
        $req->method = 'GET';
        $req->path = '/';
        $streamId = $client->send($req);
        Assert::greaterThan(
            $streamId,
            0,
            "send failed: {$client->errCode} {$client->errMsg}"
        );
        $chan->push(true);
        $resp = $client->recv();
        if (Assert::isInstanceOf(
            $resp,
            Response::class,
            "recv failed: {$client->errCode} {$client->errMsg}"
        )) {
            Assert::eq($resp->statusCode, 200);
            Assert::contains($resp->data, $domain);
        }
        $chan->pop();
    });
    go(function () use ($client, $chan) {
        Assert::eq($client->connect(), false);
        $req = new Request();
        $req->method = 'GET';
        $req->path = '/';
        $client->send($req);
        $chan->push(true);
        Assert::eq($client->recv(), false);
        $chan->pop();
    });
});

?>
--EXPECT--
