--TEST--
swoole_http_server_coro: create response
--SKIPIF--
<?php

require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Server;
use Swoole\Coroutine\Server\Connection;
use Swoole\Http\Request;
use Swoole\Http\Response;

$port = get_one_free_port();

define('GREETER', 'hello world');

Co\run(function () use ($port) {

    $server = new Server('0.0.0.0', $port, false);

    go(function () use ($server) {
        $server->handle(function (Connection $conn) use ($server) {
            $req = Request::create();
            while(true) {
                $data = $conn->recv();
                if (strlen($data) != $req->parse($data) or $req->isCompleted()) {
                    break;
                }
            }
            Assert::eq($req->get['value'], 1);
            Assert::eq($req->get['hello'], 'world');
            $resp = Response::create($conn->exportSocket());
            $resp->header('X-Server', 'swoole');
            $resp->end(GREETER);

            $server->shutdown();
        });
        $server->start();
    });

    go(function () use ($port, $server) {
        $httpClient = new Co\Http\Client(HTTP_SERVER_HOST, $port, false);
        $httpClient->setMethod("POST");
        $httpClient->setData("HELLO");
        $ok = $httpClient->execute("/rawcookie?hello=world&value=1");
        Assert::assert($ok);
        Assert::same($httpClient->statusCode, 200);
        Assert::same($httpClient->errCode, 0);
        Assert::eq($httpClient->getHeaders()['x-server'], 'swoole');
        Assert::same($httpClient->getBody(), GREETER);
        $server->shutdown();
    });
});
?>
--EXPECT--
