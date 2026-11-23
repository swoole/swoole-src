--TEST--
swoole_socket_coro: release protocol callbacks on object destruction and preserve accepted callback ownership
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine;
use Swoole\Coroutine\Socket;
use Swoole\Coroutine\Channel;

Assert::setThrowException(true);
Coroutine\run(function () {
    foreach ([false, true] as $close) {
        $socket = new Socket(AF_INET, SOCK_STREAM, 0);
        $owner = new stdClass();
        $weak = WeakReference::create($owner);
        Assert::true($socket->setProtocol([
            'open_length_check' => true,
            'package_length_func' => static function (string $data) use ($owner): int {
                return 8;
            },
        ]));
        unset($owner);
        Assert::notNull($weak->get());
        if ($close) {
            Assert::true($socket->close());
            Assert::null($weak->get());
        }
        unset($socket);
        Assert::null($weak->get());
    }
    $listener = new Socket(AF_INET, SOCK_STREAM, 0);
    Assert::true($listener->bind('127.0.0.1', 0));
    Assert::true($listener->listen());
    $owner = new stdClass();
    $weak = WeakReference::create($owner);
    Assert::true($listener->setProtocol([
        'open_length_check' => true,
        'package_length_func' => static function (string $data) use ($owner): int {
            return 8;
        },
    ]));
    unset($owner);
    $client = new Socket(AF_INET, SOCK_STREAM, 0);
    $connected = new Channel(1);
    Coroutine::create(fn () => $connected->push($client->connect('127.0.0.1', $listener->getsockname()['port'], 5)));
    $accepted = $listener->accept(5);
    Assert::isInstanceOf($accepted, Socket::class);
    Assert::true($connected->pop(5));
    Assert::true($listener->close());
    Assert::notNull($weak->get());
    unset($accepted);
    Assert::null($weak->get());
    $client->close();
});
echo "DONE\n";
?>
--EXPECT--
DONE
