--TEST--
swoole_http_server_coro: bug 2682 getData/getRawContent
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
define('PORT', get_one_free_port());
define(
    'REQUEST',
    "POST /api HTTP/1.1\r\nHost: localhost\r\nUser-Agent: curl\r\nAccept: */*\r\nContent-Type: application/json\r\nContent-Length: 28\r\n\r\n{\"id\": 1,\"name\": \"xiaoming\"}"
);

Co\run(function () {
    go(function () {
        $server = new Swoole\Coroutine\Http\Server('127.0.0.1', PORT, false);
        $server->handle('/api', function (Swoole\Http\Request $request, Swoole\Http\Response $response) use ($server) {
            var_dump(str_replace("\r\n", PHP_EOL, $request->getData()));
            echo PHP_EOL;
            var_dump($request->rawContent());
            $response->end('OK');
            Co::sleep(0.01);
            $server->shutdown();
        });
        $server->start();
    });
    go(function () {
        $client = new Swoole\Coroutine\Client(SWOOLE_TCP);
        $client->connect('127.0.0.1', PORT);
        $client->send(REQUEST);
        Assert::contains($client->recv(), '200 OK');
        $client->close();
    });
});

?>
--EXPECTF--
string(143) "POST /api HTTP/1.1
Host: localhost
User-Agent: curl
Accept: */*
Content-Type: application/json
Content-Length: 28

{"id": 1,"name": "xiaoming"}"

string(28) "{"id": 1,"name": "xiaoming"}"
