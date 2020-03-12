--TEST--
swoole_server/ssl: server verify client failed
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_openssl_version_lower_than('1.1.0');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
$pm = new SwooleTest\ProcessManager;

use Swoole\Server;

$pm->parentFunc = function ($pid) use ($pm) {
    $client = new swoole_client(SWOOLE_SOCK_TCP | SWOOLE_SSL, SWOOLE_SOCK_SYNC);
    if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
        exit("connect failed\n");
    }
    @$client->send("hello world");
    Assert::assert(@$client->recv() == "");
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $serv->set([
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
        'ssl_verify_peer' => true,
        'ssl_allow_self_signed' => true,
        'ssl_client_cert_file' => SSL_FILE_DIR . '/ca.crt',
    ]);
    $serv->on("workerStart", function (Server $serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function (Server $serv, $fd, $tid, $data) {
        $serv->send($fd, "Swoole $data");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECTF--
