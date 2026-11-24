<?php
// A coroutine HTTP/2 GET. Requires an HTTP/2 server such as
// examples/http2/server.php. Run: php examples/http2/client_get.php
use Swoole\Coroutine\Http2\Client;
use function Swoole\Coroutine\run;

run(function () {
    $client = new Client('127.0.0.1', 9501, true);
    $client->set(['ssl_verify_peer' => false, 'ssl_allow_self_signed' => true]);
    if (!$client->connect()) {
        echo 'start examples/http2/server_basic.php first' . PHP_EOL;
        return;
    }
    $request = new Swoole\Http2\Request();
    $request->path = '/';
    $request->headers = ['host' => '127.0.0.1'];
    $client->send($request);
    $response = $client->recv();
    echo $response ? 'status: ' . $response->statusCode . PHP_EOL : 'no response' . PHP_EOL;
    $client->close();
});
