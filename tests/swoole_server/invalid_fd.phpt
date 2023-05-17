--TEST--
swoole_server: invalid fd
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';
const EOF = "\r\n\r\n";

$pm = new SwooleTest\ProcessManager;
$pm->parentFunc = function () use ($pm) {
    go(function () use ($pm) {
        $client = new Co\Client(SWOOLE_SOCK_TCP);
        Assert::assert($client->connect('127.0.0.1', $pm->getFreePort()));
        Assert::notEmpty($client->send("TEST" . EOF));
        Assert::notEmpty($client->recv());
        switch_process();
        $pm->kill();
    });
};
$pm->childFunc = function () use ($pm) {
    $server = new Swoole\Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE);
    $server->set([
        'worker_num' => 1,
        'open_eof_split' => true,
        'package_eof' => EOF,
    ]);
    $server->on('workerStart', function (Swoole\Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $server->on('receive', function (Swoole\Server $serv, int $fd, int $rid, string $data) {
        Assert::false($serv->send(null, "hello {$fd}"));
        Assert::false($serv->send(-1, "hello {$fd}"));
        Assert::false($serv->send(100, "hello {$fd}"));
        Assert::false($serv->send(PHP_INT_MAX, "hello {$fd}"));
        Assert::true($serv->send($fd, "DONE\n"));
    });
    $server->start();
};
$pm->childFirst();
$pm->run();
?>
--EXPECTF--
Warning: Swoole\Server::send(): fd can not be null in %s/tests/swoole_server/invalid_fd.php on line %d

Warning: Swoole\Server::send(): invalid fd[-1] in %s/tests/swoole_server/invalid_fd.php on line %d
