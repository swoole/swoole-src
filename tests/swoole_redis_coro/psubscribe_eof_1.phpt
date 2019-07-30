--TEST--
swoole_redis_coro: redis psubscribe eof 1
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
$sock = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
$sock->bind('127.0.0.1');
$info = $sock->getsockname();
$port = $info['port'];
go(function () use ($sock) {
    $sock->listen();
    while ($client = $sock->accept(-1)) {
        $client->close();
    }
    echo "DONE\n";
});

go(function () use ($sock, $port) {
    $redis = new Swoole\Coroutine\Redis();
    $redis->connect('127.0.0.1', $port);
    for ($n = 0; $n < MAX_REQUESTS; $n++) {
        $val = $redis->psubscribe(['test.*']);
        Assert::assert($val);
        $val = $redis->recv();
        Assert::false($val);
        Assert::false($redis->connected);
        Assert::assert(in_array($redis->errType, [SWOOLE_REDIS_ERR_IO, SWOOLE_REDIS_ERR_EOF], true));
        if ($redis->errType === SWOOLE_REDIS_ERR_IO) {
            Assert::same($redis->errCode, SOCKET_ECONNRESET);
        }
    }
    $redis->close();
    $sock->close();
});
swoole_event_wait();
?>
--EXPECT--
DONE
