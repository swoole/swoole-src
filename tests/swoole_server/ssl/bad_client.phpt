--TEST--
swoole_server/ssl: ssl bad client
--SKIPIF--
<?php require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

define('ERROR_FILE', __DIR__.'/ssl_error');

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    $client = new swoole_client(SWOOLE_SOCK_TCP, SWOOLE_SOCK_SYNC); //同步阻塞
    if (!$client->connect('127.0.0.1', $pm->getFreePort()))
    {
        exit("connect failed\n");
    }
    $client->send("hello world");
    Assert::same($client->recv(), "");
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $serv->set(
        [
            'log_file' => ERROR_FILE,
            'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
            'ssl_key_file' => SSL_FILE_DIR . '/server.key',
        ]
    );
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
readfile(ERROR_FILE);
unlink(ERROR_FILE);
?>
--EXPECTF--
[%s]	WARNING	Socket::ssl_accept(): bad SSL client[127.0.0.1:%d], reason=%d, error_string=%s
