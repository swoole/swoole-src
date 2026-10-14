--TEST--
swoole_http_client_coro/websocket: ssl recv [2]
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

Co\run(function () {
    $port = get_one_free_port();
    $server = new Co\Http\Server('127.0.0.1', $port, true);
    $server->set([
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    ]);
    $server->handle('/websocket', function ($request, $websocket) {
        Assert::true($websocket->upgrade());
        Assert::same($websocket->recv()->data, 'subscribe');
        $websocket->push('subscribed');
        $websocket->push('snapshot');
    });

    go(function () use ($server) {
        $server->start();
    });

    $client = new Co\Http\Client('127.0.0.1', $port, true);
    $client->set(['timeout' => 5]);
    Assert::true($client->upgrade('/websocket'));
    Assert::true($client->push('subscribe'));
    Assert::same($client->recv()->data, 'subscribed');
    Assert::same($client->recv()->data, 'snapshot');
    $server->shutdown();

    echo "DONE\n";
});
?>
--EXPECT--
DONE
