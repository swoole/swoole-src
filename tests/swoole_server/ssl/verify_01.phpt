--TEST--
swoole_server/ssl: server verify client success
--SKIPIF--
<?php
require __DIR__ . '/../../include/skipif.inc';
skip_if_openssl_version_lower_than('1.1.0');
?>
--FILE--
<?php
require __DIR__ . '/../../include/bootstrap.php';

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP | SWOOLE_SSL);
        $client->set([
            'ssl_cert_file' => __DIR__ . '/../../include/api/ssl-ca/client-cert.pem',
            'ssl_key_file' => __DIR__ . '/../../include/api/ssl-ca/client-key.pem',
        ]);
        if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
            exit("connect failed\n");
        }
        $client->send("hello world");
        Assert::same($client->recv(), "Swoole hello world");
    });
    Swoole\Event::wait();
    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $serv->set([
        'ssl_cert_file' => __DIR__ . '/../../include/api/ssl-ca/server-cert.pem',
        'ssl_key_file' => __DIR__ . '/../../include/api/ssl-ca/server-key.pem',
        'ssl_verify_peer' => true,
        'ssl_allow_self_signed' => true,
        'ssl_client_cert_file' => __DIR__ . '/../../include/api/ssl-ca/ca-cert.pem',
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
DONE
