--TEST--
swoole_redis_coro: auto reconnect after server side close the connection
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

use Swoole\Redis\Server;

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    Co\run(function () use ($pm) {
        $redis = new Swoole\Coroutine\Redis;
        $ret = $redis->connect('127.0.0.1', $pm->getFreePort());
        Assert::true($ret);
        for ($n = MAX_REQUESTS; $n--;) {
            $ret = $redis->set('random_val', $random = get_safe_random(128));
            Assert::true($ret, "code: {$redis->errCode}, msg={$redis->errMsg}");
            $ret = $redis->get('random_val');
            Assert::true($ret && $ret === $random, "code: {$redis->errCode}, msg={$redis->errMsg}");
            Co::sleep(0.001);
        }
        $redis->setOptions(['reconnect' => false]);
        for ($n = MAX_REQUESTS; $n--;) {
            $ret = $redis->set('random_val', $random = get_safe_random(128));
            Assert::true($n === MAX_REQUESTS ? $ret : !$ret);
            $ret = $redis->get('random_val');
            Assert::true($n === MAX_REQUESTS ? ($ret && $ret === $random) : !$ret);
            Co::sleep(0.001);
        }
    });
    $pm->kill();
    echo "DONE\n";
};
$pm->childFunc = function () use ($pm) {
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->data = [];
    $server->on('WorkerStart', function ($server) use ($pm) {
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
        $server->close($fd);
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
DONE
