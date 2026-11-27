--TEST--
swoole_socket_coro: recvmsg (PHP sockets-compatible message array)
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Coroutine\Socket;
use Swoole\Event;

go(function () {
    $server = new Socket(AF_INET, SOCK_DGRAM, 0);
    Assert::true($server->bind('127.0.0.1', 0));
    $sinfo = $server->getsockname();
    $sport = (int) $sinfo['port'];

    $client = new Socket(AF_INET, SOCK_DGRAM, 0);
    $payload = 'hello-recvmsg';

    Assert::same($client->sendto('127.0.0.1', $sport, $payload), strlen($payload));

    $msg = [
        'buffer_size' => 2048,
        'controllen' => 0,
    ];
    $n = $server->recvmsg($msg, 0, 3);
    Assert::same($n, strlen($payload));
    Assert::same($msg['iov'][0], $payload);
    Assert::same($msg['name']['address'], '127.0.0.1');
    Assert::true($msg['name']['port'] > 0);
    Assert::same($msg['flags'], 0);
    Assert::true(is_array($msg['control']));

    echo "OK\n";
});
Event::wait();
?>
--EXPECT--
OK
