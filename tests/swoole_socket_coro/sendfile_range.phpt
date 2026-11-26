--TEST--
swoole_socket_coro: sendFile sends exactly the requested range over TCP and TLS
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/Assert.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Socket;
use SwooleTest\Assert;

Assert::setThrowException(true);
$file = tempnam(sys_get_temp_dir(), 'swoole-sendfile-range-');
Assert::notSame($file, false);
try {
    Assert::same(file_put_contents($file, '0123456789'), 10);
    Coroutine\run(function () use ($file) {
        foreach (defined('SWOOLE_SSL') ? [false, true] : [false] as $ssl) {
            $listener = new Socket(AF_INET, SOCK_STREAM, 0);
            $reader = new Socket(AF_INET, SOCK_STREAM, 0);
            if ($ssl) {
                $certDir = __DIR__ . '/../include/ssl_certs';
                Assert::true($listener->setProtocol([
                    'open_ssl' => true,
                    'ssl_cert_file' => $certDir . '/server.crt',
                    'ssl_key_file' => $certDir . '/server.key',
                ]));
                Assert::true($reader->setProtocol(['open_ssl' => true]));
            }
            Assert::true($listener->bind('127.0.0.1', 0) && $listener->listen());
            Coroutine::create(function () use ($listener, $file, $ssl) {
                $writer = $listener->accept(2);
                Assert::true($writer instanceof Socket);
                try {
                    if ($ssl) {
                        Assert::true($writer->sslHandshake());
                    }
                    Assert::same($writer->recvAll(1, 2), 'R');
                    Assert::false($writer->sendFile($file, 10));
                    Assert::same($writer->errCode, SOCKET_EINVAL);
                    Assert::false($writer->sendFile($file, 11, 1));
                    Assert::same($writer->errCode, SOCKET_EINVAL);
                    Assert::true($writer->sendFile($file, 2, 3));
                    Assert::same($writer->sendAll('|', 2), 1);
                    Assert::true($writer->sendFile($file, 7));
                    Assert::same($writer->sendAll('!', 2), 1);
                } finally {
                    $writer->close();
                }
            });
            try {
                Assert::true($reader->connect('127.0.0.1', $listener->getsockname()['port'], 2));
                Assert::same($reader->sendAll('R', 2), 1);
                Assert::same($reader->recvAll(8, 2), '234|789!');
            } finally {
                $reader->close();
                $listener->close();
            }
        }
    });
} finally {
    unlink($file);
}
echo "DONE\n";
?>
--EXPECT--
DONE
