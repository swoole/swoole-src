--TEST--
swoole_server: bug Github#2639
--SKIPIF--
<?php
require __DIR__ . '/../include/skipif.inc';
skip_if_openssl_version_lower_than('1.1.0');
?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    go(function () use ($pm) {
        $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_TCP | SWOOLE_SSL);
        $client->set([
            'ssl_cert_file' => dirname(__DIR__) . '/include/api/ssl-ca/client-cert.pem',
            'ssl_key_file' => dirname(__DIR__) . '/include/api/ssl-ca/client-key.pem',
        ]);
        if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
            exit("connect failed\n");
        }
        $client->send("hello world");
        $data = $client->recv();
        Assert::assert($data);
        $json = json_decode($data, true);
        Assert::isArray($json);
        Assert::same($json['subject']['O'], 'swoole');
    });
    Swoole\Event::wait();
    $pm->kill();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm) {
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $serv->set([
        'log_file' => '/dev/null',
        'ssl_cert_file' => dirname(__DIR__) . '/include/api/ssl-ca/server-cert.pem',
        'ssl_key_file' => dirname(__DIR__) . '/include/api/ssl-ca/server-key.pem',
        'ssl_verify_peer' => true,
        'ssl_allow_self_signed' => true,
        'task_worker_num' => 1,
        'ssl_client_cert_file' => dirname(__DIR__) . '/include/api/ssl-ca/ca-cert.pem',
    ]);
    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function ($serv, $fd, $tid, $data) {
        $cert_file = $serv->getClientInfo($fd)['ssl_client_cert'];
        $serv->send($fd, json_encode(openssl_x509_parse($cert_file)));
        $serv->task(['fd' => $fd]);
    });

    $serv->on('task', function($serv, $taskId, $wid, $data) {
        $info = $serv->getClientInfo($data['fd']);
        Assert::isArray($info);
        Assert::assert(!array_key_exists('ssl_client_cert', $info));
    });

    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
