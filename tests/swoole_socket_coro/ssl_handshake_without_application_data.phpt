--TEST--
swoole_socket_coro: TLS 1.3 handshake completes without application data
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_no_ssl();
skip('requires TLS 1.3', !defined('SWOOLE_SSL_TLSv1_3'));
?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Channel;
use Swoole\Coroutine\Socket;
use SwooleTest\Assert;

Assert::setThrowException(true);
Coroutine::set(['socket_read_timeout' => 2, 'socket_write_timeout' => 2]);
Coroutine\run(function () {
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    $client = new Socket(AF_INET, SOCK_STREAM, 0);
    $certDir = __DIR__ . '/../include/ssl_certs';
    $tls = ['open_ssl' => true, 'ssl_protocols' => SWOOLE_SSL_TLSv1_3];
    Assert::true($listener->setProtocol($tls + [
        'ssl_cert_file' => $certDir . '/server.crt',
        'ssl_key_file' => $certDir . '/server.key',
    ]));
    Assert::true($client->setProtocol($tls + ['ssl_verify_peer' => false]));
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());
    $port = $listener->getsockname()['port'];
    $handshake = new Channel(1);

    Coroutine::create(function () use ($listener, $handshake) {
        $peer = $listener->accept(2);
        Assert::isInstanceOf($peer, Socket::class);
        try {
            $handshake->push([$peer->sslHandshake(), $peer->errCode]);
        } finally {
            $peer->close();
        }
    });

    try {
        Assert::true($client->connect('127.0.0.1', $port, 2));
        // Keep the connection open until the peer confirms the handshake, without sending any application data.
        $result = $handshake->pop(3);
        Assert::isArray($result);
        [$completed, $error] = $result;
        Assert::true($completed, "Peer TLS handshake failed with socket error $error");
        Assert::same($error, 0);
    } finally {
        $client->close();
        $listener->close();
    }
});
echo "DONE\n";
?>
--EXPECT--
DONE
