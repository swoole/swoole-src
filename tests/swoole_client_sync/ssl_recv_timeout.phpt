--TEST--
swoole_client_sync: ssl recv timeout

--SKIPIF--
<?php require  __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;
$pm->parentFunc = function ($pid) use ($pm)
{
    $cli = new swoole_client(SWOOLE_SOCK_TCP | SWOOLE_SSL, SWOOLE_SOCK_SYNC);
    $r = $cli->connect('127.0.0.1', 9501, 5);
    assert($r);
    $cli->send("hello world\n");
    $time = time();
    $data = $cli->recv(1024);
    assert(time() - $time < 2);
    assert($data === "Swoole hello world\n");
    $pm->kill();
};

$pm->childFunc = function () use ($pm, $port)
{
    $serv = new swoole_server("127.0.0.1", 9501, SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $serv->set([
        'log_file' => '/dev/null',
        'ssl_cert_file' => dirname(__DIR__) . '/include/api/swoole_http_server/localhost-ssl/server.crt',
        'ssl_key_file' => dirname(__DIR__) . '/include/api/swoole_http_server/localhost-ssl/server.key',
    ]);
    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function ($serv, $fd, $tid, $data) {
        $serv->send($fd, "Swoole $data");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--

