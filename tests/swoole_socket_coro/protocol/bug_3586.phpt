--TEST--
swoole_socket_coro/protocol: bug GitHub#3586
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Socket;

const GREETER = 'Hello Swoole';
const CO_NUM = 5;
$GLOBALS['counter'] = 0;

Coroutine\run(function () {
    $server = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Coroutine::create(function () use ($server) {
        Assert::assert($server->bind('127.0.0.1'));
        $server->setProtocol([
            'open_length_check' => true,
            'package_length_func' => function (string $data) {
                if (strlen($data) < strlen(GREETER)) {
                    return 0;
                } else {
                    return strlen(GREETER);
                }
            }
        ]);
        Assert::assert($server->listen());
        while (true) {
            $client = $server->accept(-1);
            if (!$client) {
                break;
            }
            /* @var $client Socket */
            Coroutine::create(function () use ($client, $server) {
                Assert::isInstanceOf($client, Socket::class);
                Assert::eq($client->recvPacket(), GREETER);
                Assert::greaterThan($client->sendAll(GREETER), 1);
                $client->close();
                $GLOBALS['counter'] ++;
                if ($GLOBALS['counter'] == CO_NUM) {
                    $server->close();
                }
            });
        }
    });

    for ($i = 0; $i < CO_NUM; $i++) {
        Coroutine::create(function () use ($server) {
            $client = new Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
            Assert::true($client->connect('127.0.0.1', $server->getsockname()['port']));
            if (rand(0, 5) > 3) {
                $client->send(substr(GREETER, 0, 5));
                Co::sleep(0.1);
                $client->send(substr(GREETER, 5));
            } else {
                $client->send(GREETER);
            }
            Assert::eq($client->recvPacket(), GREETER);
            $client->close();
        });
    }
});
?>
--EXPECT--
