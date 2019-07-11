--TEST--
swoole_redis_server: test big packet
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Redis\Server;

define('VALUE_LEN',  8192 * 128);

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    $redis = new redis;
    $redis->connect('127.0.0.1', $pm->getFreePort());
    $redis->set('big_value', str_repeat('A', VALUE_LEN));
    $ret = $redis->get('big_value');
    Assert::same(strlen($ret ?? '' ?: ''), VALUE_LEN);
    swoole_process::kill($pid);
};

$pm->childFunc = function () use ($pm)
{
    $server = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->data = array();

    $server->setHandler('GET', function ($fd, $data) use ($server) {
        if (count($data) == 0)
        {
            return Server::format(Server::ERROR, "ERR wrong number of arguments for 'GET' command");
        }
        $key = $data[0];
        if (empty($server->data[$key]))
        {
            $server->send($fd, Server::format(Server::NIL));
        }
        else
        {
            $server->send($fd, Server::format(Server::STRING, $server->data[$key]));
        }
    });

    $server->setHandler('SET', function ($fd, $data) use ($server) {
        if (count($data) < 2)
        {
            return Server::format(Server::ERROR, "ERR wrong number of arguments for 'SET' command");
        }
        $key = $data[0];
        $server->data[$key] = $data[1];
        $server->send($fd, Server::format(Server::STATUS, 'OK'));
    });

    $server->on('WorkerStart', function ($server) use ($pm) {
        $pm->wakeup();
    });

    $server->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
