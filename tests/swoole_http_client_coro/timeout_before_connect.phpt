--TEST--
swoole_http_client_coro: use timeout and timeout before connect
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Co\run(function () {
    $server = new Co\Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($server->setProtocol([
        'open_ssl'      => true,
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file'  => SSL_FILE_DIR . '/server.key',
    ]));
    Assert::true($server->bind('127.0.0.1', 0));
    Assert::true($server->listen());
    $port = $server->getsockname()['port'];
    go(function () use ($server) {
        for ($i = 0; $i < 3; $i++) {
            $peer = $server->accept(2);
            Assert::isInstanceOf($peer, Co\Socket::class);
            go(function () use ($peer, $i) {
                if ($i !== 1) {
                    // Keep the TLS handshake pending independently of connect/network speed.
                    Co::sleep(0.2);
                    $peer->close();
                    return;
                }
                Assert::true($peer->sslHandshake());
                Assert::notEmpty($peer->recv(8192, 2));
                $response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
                Assert::same($peer->sendAll($response), strlen($response));
                $peer->close();
            });
        }
        $server->close();
    });
    $client1 = new Co\Http\Client('127.0.0.1', $port, true);
    $client1->set(['timeout' => 0.02]);
    $client1->setDefer(true);
    Assert::false($client1->get('/'));
    Assert::same($client1->errCode, SOCKET_ETIMEDOUT);
    Assert::same($client1->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_CONNECT_FAILED);
    Assert::false($client1->recv());
    Assert::same($client1->errCode, SWOOLE_ERROR_CLIENT_NO_CONNECTION);

    $client2 = new Co\Http\Client('127.0.0.1', $port, true);
    $client2->set(['timeout' => 2]);
    $client2->setDefer(true);
    Assert::true($client2->get('/'));
    Assert::false($client1->get('/'));
    Assert::same($client1->errCode, SOCKET_ETIMEDOUT);
    Assert::same($client1->statusCode, SWOOLE_HTTP_CLIENT_ESTATUS_CONNECT_FAILED);
    Assert::false($client1->recv());
    Assert::same($client1->errCode, SWOOLE_ERROR_CLIENT_NO_CONNECTION);
    Assert::true($client2->recv());
    Assert::same($client2->errCode, 0);
    Assert::same($client2->statusCode, 200);
    Assert::same($client2->body, 'OK');
    $client1->close();
    $client2->close();
});
?>
--EXPECT--
