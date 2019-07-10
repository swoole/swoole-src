--TEST--
swoole_redis_coro: do not retry after server down
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Redis\Server;

$pm = new ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $redis = new Swoole\Coroutine\Redis;
        $ret = $redis->connect('127.0.0.1', $pm->getFreePort());
        Assert::assert($ret);
        $ret = $redis->set('random_val', $random = get_safe_random(128));
        Assert::assert($ret);
        $ret = $redis->get('random_val');
        Assert::same($ret, $random);
        $pm->kill();
        Assert::assert(!$redis->get('random_val'));
        Assert::same($redis->errCode, SOCKET_ECONNRESET);
        for ($n = MAX_REQUESTS; $n--;) {
            Assert::assert(!$redis->set('random_val', get_safe_random(128)));
            Assert::same($redis->errCode, SOCKET_ECONNREFUSED);
            Assert::assert(!$redis->get('random_val'));
            Assert::same($redis->errCode, SOCKET_ECONNREFUSED);
        }
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->data = [];
    $server->on('workerStart', function ($server) use ($pm) {
        $pm->wakeup();
    });
    $server->setHandler('GET', function ($fd, $data) use ($server) {
        if (count($data) == 0) {
            return Server::format(Server::ERROR, "ERR wrong number of arguments for 'GET' command");
        }
        $key = $data[0];
        if (empty($server->data[$key])) {
            $server->send($fd, Server::format(Server::NIL));
        } else {
            $server->send($fd, Server::format(Server::STRING, $server->data[$key]));
        }
    });
    $server->setHandler('SET', function ($fd, $data) use ($server) {
        if (count($data) < 2) {
            $server->send($fd, Server::format(Server::ERROR, "ERR wrong number of arguments for 'SET' command"));
        }
        $key = $data[0];
        $server->data[$key] = $data[1];
        $server->send($fd, Server::format(Server::STATUS, 'OK'));
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECT--
