--TEST--
swoole_socket_coro: recv/send all
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
define('BIG_RANDOM_DATA', str_repeat(get_safe_random(1024), 64 * 1024));
define('BIG_RANDOM_DATA_LENGTH', strlen(BIG_RANDOM_DATA));
$server = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
$port = get_one_free_port();
go(function () use ($server, $port) {
    Assert::assert($server->bind('127.0.0.1', $port));
    Assert::assert($server->listen(512));
    $conn_map = [];
    while ($conn = $server->accept()) {
        Assert::assert($conn instanceof  Co\Socket);
        Assert::assert($conn->fd > 0);
        $conn_map[$conn->fd] = $conn;
        go(function () use ($conn) {
            Assert::assert($conn instanceof Swoole\Coroutine\Socket);
            Assert::assert($conn->recvAll(BIG_RANDOM_DATA_LENGTH) === BIG_RANDOM_DATA);
            Assert::assert($conn->sendAll(BIG_RANDOM_DATA) === BIG_RANDOM_DATA_LENGTH);
        });
    }
});
go(function () use ($server, $port) {
    $conn = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    Assert::assert($conn->connect('127.0.0.1', $port));
    Assert::assert($conn->sendAll(BIG_RANDOM_DATA) === BIG_RANDOM_DATA_LENGTH);
    Assert::assert($conn->recvAll(BIG_RANDOM_DATA_LENGTH) === BIG_RANDOM_DATA);
    Assert::assert($server->close());
});
Swoole\Event::wait();
echo "DONE\n";
?>
--EXPECT--
DONE
