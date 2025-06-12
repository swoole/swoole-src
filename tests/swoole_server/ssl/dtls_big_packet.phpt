--TEST--
swoole_server/ssl: big dtls packet
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';
use Swoole\Client;
use Swoole\Server;
use SwooleTest\ProcessManager;

$pm = new ProcessManager();

const PKT_LEN = IS_MAC_OS ? 8000 : 16000;

$pm->parentFunc = function ($pid) use ($pm) {
    $client = new Client(SWOOLE_SOCK_UDP | SWOOLE_SSL, SWOOLE_SOCK_SYNC); // 同步阻塞
    if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
        exit("connect failed\n");
    }
    // TLS max record size = 16K
    $client->send('hello world' . str_repeat('A', PKT_LEN));
    Assert::same($client->recv(65535), 'Swoole hello world' . str_repeat('A', PKT_LEN));
    $pm->kill();
};

$pm->childFunc = function () use ($pm) {
    $serv = new Server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_UDP | SWOOLE_SSL);
    $serv->set([
        'log_file' => '/dev/null',
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    ]);
    $serv->on('workerStart', function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function ($serv, $fd, $tid, $data) {
        $serv->send($fd, "Swoole {$data}");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
