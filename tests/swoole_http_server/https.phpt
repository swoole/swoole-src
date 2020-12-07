--TEST--
swoole_http_server: https
--SKIPIF--
<?php require __DIR__ . '/../include/skipif.inc'; ?>
--FILE--
<?php
require __DIR__ . '/../include/bootstrap.php';

$pm = new ProcessManager;

$html = base64_encode(random_bytes(rand(2048, 65536)));

$pm->parentFunc = function ($pid) use ($pm, $html) {
    go(function () use ($pm, $html) {
        $data = httpGetBody("https://127.0.0.1:{$pm->getFreePort()}/");
        Assert::same($data, $html);
        $pm->kill();
    });
    Swoole\Event::wait();
    echo "DONE\n";
};

$pm->childFunc = function () use ($pm, $html) {
    $serv = new swoole_http_server('127.0.0.1', $pm->getFreePort(), SWOOLE_PROCESS, SWOOLE_SOCK_TCP | SWOOLE_SSL);
    $serv->set([
        'log_file' => '/dev/null',
        'ssl_cert_file' => SSL_FILE_DIR.'/server.crt',
        'ssl_key_file' => SSL_FILE_DIR.'/server.key',
    ]);
    $serv->on("workerStart", function ($serv) use ($pm) {
        $pm->wakeup();
    });
    $serv->on('request', function ($req, $resp) use ($html) {
        $resp->end($html);
    });
    $serv->start();
};

$pm->childFirst();
$pm->run();
?>
--EXPECT--
DONE
