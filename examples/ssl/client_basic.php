<?php
// A coroutine HTTPS client against a self-signed server.
// Start examples/ssl/webserver.php first, then run this.
// Run: php examples/ssl/client_basic.php
use Swoole\Coroutine\Http\Client;
use function Swoole\Coroutine\run;

run(function () {
    $client = new Client('127.0.0.1', 9501, true);
    $client->set(['ssl_verify_peer' => false, 'ssl_allow_self_signed' => true]);
    $client->get('/');
    if ($client->errCode !== 0) {
        echo 'start examples/ssl/webserver.php first' . PHP_EOL;
        return;
    }
    echo 'status: ', $client->statusCode, PHP_EOL;
    $client->close();
});
