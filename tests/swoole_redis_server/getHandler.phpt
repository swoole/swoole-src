--TEST--
swoole_redis_server: getHandler
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
use Swoole\Redis\Server;

$server = new Server('127.0.0.1', 0, SWOOLE_BASE);

$server->setHandler('GET', function ($fd, $data) use ($server) {
    $server->send($fd, Server::format(Server::STRING, "hello"));
});

$callback = $server->getHandler('GET');
Assert::assert(is_callable($callback));

?>
--EXPECT--
