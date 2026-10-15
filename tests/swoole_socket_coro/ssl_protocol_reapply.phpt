--TEST--
swoole_socket_coro: reapplying SSL settings preserves the context and accepted sockets remain usable
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Assert::setThrowException(true);
Swoole\Coroutine\run(function () {
    $server = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
    $settings = [
        'open_ssl' => true,
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    ];
    Assert::true($server->setProtocol($settings));
    Assert::true($server->setProtocol($settings));
    Assert::true($server->bind('127.0.0.1', 0));
    Assert::true($server->listen());
    $port = $server->getsockname()['port'];

    $cid = Swoole\Coroutine::create(function () use ($server, $settings) {
        $socket = $server->accept(2);
        Assert::isInstanceOf($socket, Swoole\Coroutine\Socket::class);
        Assert::true($socket->setProtocol($settings));
        Assert::true($socket->sslHandshake());
        Assert::same($socket->recvAll(4, 2), 'PING');
        Assert::same($socket->sendAll('PONG'), 4);
        $socket->close();
    });
    $client = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($client->setProtocol(['open_ssl' => true, 'ssl_verify_peer' => false]));
    Assert::true($client->setProtocol(['open_ssl' => true]));
    Assert::true($client->connect('127.0.0.1', $port, 2));
    Assert::same($client->sendAll('PING'), 4);
    Assert::same($client->recvAll(4, 2), 'PONG');
    $client->close();
    Swoole\Coroutine::join([$cid]);
    $server->close();
});
echo "DONE\n";
?>
--EXPECT--
DONE
