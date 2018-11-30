--TEST--
swoole_redis_coro: redis psubscribe
--SKIPIF--
<?php require __DIR__.'/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__.'/../include/bootstrap.php';

use Swoole\Coroutine as co;

const N = 100;

$sock = new Swoole\Coroutine\Socket(AF_INET, SOCK_STREAM, 0);
$sock->bind('127.0.0.1');
$info = $sock->getsockname();
$port = $info['port'];

go(
    function () use ($sock)
    {
        $sock->listen();
        $client = $sock->accept();
        if ($client) {
            $client->close();
        }
        $sock->close();
    }
);

go(
    function () use ($port)
    {
        $redis = new co\Redis();
        $redis->connect('127.0.0.1', $port);
        for ($i = 0; $i < N; $i++) {
            $val = $redis->psubscribe(['test.*']);
            assert($val == false);
            assert($redis->connected == false);
            assert($redis->errCode == 3);
        }
        $redis->close();
    }
);
swoole_event_wait();
?>
--EXPECT--
