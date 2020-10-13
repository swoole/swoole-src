--TEST--
swoole_client_coro: dtls
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new SwooleTest\ProcessManager;

$pm->parentFunc = function ($pid) use ($pm) {
    Co\run(
        function () use ($pm) {
            $client = new Swoole\Coroutine\Client(SWOOLE_SOCK_UDP | SWOOLE_SSL);
            if (!$client->connect('127.0.0.1', $pm->getFreePort())) {
                exit("connect failed\n");
            }
            $client->send("hello world");
            Assert::same($client->recv(), "Swoole hello world");
            $pm->kill();
        }
    );
};

$pm->childFunc = function () use ($pm) {
    $serv = new swoole_server('127.0.0.1', $pm->getFreePort(), SWOOLE_BASE, SWOOLE_SOCK_UDP | SWOOLE_SSL);
    $serv->set([
        //'log_file' => '/dev/null',
        'ssl_cert_file' => SSL_FILE_DIR . '/server.crt',
        'ssl_key_file' => SSL_FILE_DIR . '/server.key',
    ]);
    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('receive', function ($serv, $fd, $tid, $data) {
        $serv->send($fd, "Swoole $data");
    });
    $serv->on('packet', function ($serv, $fd, $tid, $data) {
        $serv->send($fd, "Swoole $data");
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
