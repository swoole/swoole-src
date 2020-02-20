--TEST--
swoole_socket_coro/protocol: package_length_func
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Socket;

const GREETER = 'Hello Swoole';

Coroutine\run(function () {
    $server = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Coroutine::create(function () use ($server) {
        Assert::assert($server->bind('127.0.0.1'));
        Assert::assert($server->listen());
        while (true) {
            $client = $server->accept(-1);
            if (!$client) {
                break;
            }
            /* @var $client Socket */
            Coroutine::create(function () use ($client) {
                Assert::isInstanceOf($client, Socket::class);
                for ($n = 0; $n < strlen(GREETER); $n++) {
                    Assert::eq($client->sendAll(GREETER[$n]), 1);
                    Coroutine::sleep(0.01);
                }
                $client->close();
            });
        }
        $server->close();
    });
    Coroutine::create(function () use ($server) {
        $client = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        Assert::true($client->connect('127.0.0.1', $server->getsockname()['port']));
        $client->setProtocol([
            'open_length_check' => true,
            'package_length_func' => function (string $data) {
                if (strlen($data) < strlen(GREETER)) {
                    return 0;
                } else {
                    return strlen(GREETER);
                }
            }
        ]);
        var_dump($client->recvPacket());
        $client->close();
        $server->close();
    });
});

?>
--EXPECT--
string(12) "Hello Swoole"
