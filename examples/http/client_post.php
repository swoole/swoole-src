<?php
// A coroutine HTTP POST with a form body.
// Start examples/http/hello.php first, then run this.
// Run: php examples/http/client_post.php
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

run(function () {
    $client = new Client('127.0.0.1', 9501);
    $client->setHeaders(['Content-Type' => 'application/x-www-form-urlencoded']);
    $client->post('/', ['name' => 'swoole']);
    echo 'status: ', $client->statusCode, PHP_EOL;
    echo 'body: ', $client->body, PHP_EOL;
    $client->close();
});
