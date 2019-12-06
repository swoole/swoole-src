--TEST--
swoole_socket_coro: server and client concurrency
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

Swoole\Runtime::enableCoroutine();

$port = get_one_free_port();
go(function () use ($port) {
    $socket = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::assert($socket->bind('127.0.0.1', $port));
    Assert::assert($socket->listen(MAX_CONCURRENCY_MID));
    $i = 0;
    while ($conn = $socket->accept()) {
        go(function () use ($socket, $conn, &$i) {
            for ($n = MAX_REQUESTS; $n--;) {
                $data = $conn->recv(tcp_length($conn->recv(tcp_type_length())));
                Assert::same($data, "Hello Swoole Server #{$n}!");
                $conn->send(tcp_pack("Hello Swoole Client #{$n}!"));
            }
            $conn->close();
            if (++$i === MAX_CONCURRENCY_MID) {
                $socket->close();
                echo "DONE\n";
            }
        });
    }
});
for ($c = MAX_CONCURRENCY_MID; $c--;) {
    go(function () use ($port) {
        $client = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
        Assert::assert($client->connect('127.0.0.1', $port));
        for ($n = MAX_REQUESTS; $n--;) {
            $client->send(tcp_pack("Hello Swoole Server #{$n}!"));
            $data = $client->recv(tcp_length($client->recv(tcp_type_length())));
            Assert::same($data, "Hello Swoole Client #{$n}!");
        }
        $client->close();
    });
}

?>
--EXPECT--
DONE
